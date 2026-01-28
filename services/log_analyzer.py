import re
from collections import defaultdict, deque
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
from html import escape
from ipaddress import ip_address, ip_network
from typing import Dict, List, Optional, Tuple


# =====================
# Data models
# =====================
@dataclass
class Event:
    timestamp: Optional[datetime]
    level: Optional[str]
    service: Optional[str]
    message: str
    kv: Dict[str, str] = field(default_factory=dict)
    ip: Optional[str] = None
    user: Optional[str] = None
    endpoint: Optional[str] = None
    status: Optional[str] = None
    filename: Optional[str] = None
    query: Optional[str] = None
    event_type: str = "unknown"
    raw: str = ""


@dataclass
class Finding:
    rule_name: str
    description: str
    severity: str
    matched_lines: List[str]
    risk_score: int
    confidence: float = 0.6

    def to_safe_dict(self) -> Dict:
        d = asdict(self)
        # HTML-escape textual fields at the end
        d['rule_name'] = escape(d['rule_name'])
        d['description'] = escape(d['description'])
        # Do not escape matched_lines here; UI renders via textContent/x-text to avoid double-escaping
        return d


# =====================
# Configuration
# =====================
CONFIG = {
    'debug': False,
    'allowlists': {
        'ips': {"127.0.0.1", "::1"},
        'endpoints': {"/health", "/status", "/livez", "/readyz"},
        'internal_cidrs': ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"],
        'allow_internal': False,
    },
    'thresholds': {
        'brute_force_count': 5,
        'brute_force_window_sec': 300,  # 5 min
        'spray_unique_users': 5,
        'spray_window_sec': 600,  # 10 min
        'fail_then_success_window_sec': 600,
        'waf_plus_auth_window_sec': 600,
        'port_scan_unique_ports': 8,
    },
    'scoring': {
        # atomic
        'auth_fail': 5,
        'auth_success': 0,
        'account_lockout': 30,
        'waf_sqli': 45,
        'waf_xss': 40,
        'waf_traversal': 35,
        'file_upload_blocked': 40,
        'port_scan': 30,
        'sudo_exec': 10,
        'privilege_change': 65,
        'app_error': 1,
        # correlation adders
        'brute_force': 35,
        'password_spraying': 35,
        'fail_then_success': 40,
        'waf_plus_auth': 25,
        'multi_port_scan': 35,
    },
    'event_type_patterns': {
        # English + Swedish
        'auth_fail': [
            r'failed password', r'authentication failure', r'invalid user', r'login failed',
            r'misslyckad inlogg', r'misslyckat lösenord', r'felaktig lösenord', r'autentisering misslyckades', r'ogiltig användare',
        ],
        'auth_success': [
            r'accepted password', r'login success', r'authentication succeeded',
            r'inloggning lyckades', r'autentisering lyckades',
        ],
        'account_lockout': [r'account locked', r'ACCOUNT LOCKED', r'kontot låst', r'konto låst', r'too many failures'],
        'waf_sqli': [
            r'union\s+select', r'\bor\b\s*1=1', r'sqlmap', r'sqli', r'information_schema', r'select%20',
            r'sql-?inj(ektion)?',
        ],
        'waf_xss': [r'<script', r'onerror\s*=', r'javascript:', r'\bxss\b'],
        'waf_traversal': [r'\.\./', r'%2e%2e%2f', r'\.\.\\', r'etc/passwd', r'katalogtravers'],
        'port_scan': [r'port scan', r'nmap scan', r'portskann', r'port skann'],
        'file_upload_blocked': [r'upload blocked', r'file upload blocked', r'malicious file', r'blocked content', r'uppladdning blockerad', r'filuppladdning blockerad', r'otillåten filuppladdning', r'skadlig fil'],
        'privilege_change': [r'uid=0', r'added to sudoers', r'role\s*admin', r'behörighet', r'privilege', r'sudo:'],
        'app_error': [r'\berror\b', r'exception', r'fel:'],
        'sudo_exec': [r'\bsudo\b.*COMMAND=|sudo:'],
        'port_event': [r'port=\d+', r':\d+'],
    },
}


# =====================
# Parsing and normalization
# =====================
_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")


def _parse_kv(rest: str) -> Tuple[Dict[str, str], str]:
    """Parse key=value pairs, including quoted values, and return remaining message reliably.

    Supports:
      key=value
      key="value with spaces"
      key='value with spaces'
    """
    kv: Dict[str, str] = {}
    spans: List[Tuple[int, int]] = []
    pattern = re.compile(r"(\b[\w.-]+)\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s]+))")
    for m in pattern.finditer(rest):
        key = m.group(1).lower()
        val = next(v for v in (m.group(2), m.group(3), m.group(4)) if v is not None)
        kv[key] = val
        spans.append(m.span())

    if not spans:
        return kv, rest.strip()

    # Remove spans from message without using string replace
    spans.sort()
    parts: List[str] = []
    last = 0
    for s, e in spans:
        if last < s:
            parts.append(rest[last:s])
        last = e
    if last < len(rest):
        parts.append(rest[last:])

    msg = re.sub(r"\s+", " ", " ".join(p.strip() for p in parts if p.strip())).strip()
    return kv, msg


def parse_line(line: str) -> Event:
    line = line.rstrip("\n")
    # Format 1: YYYY-MM-DD HH:MM:SS LEVEL [service] message key=val
    m1 = re.match(r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(?P<level>[A-Z]+)\s+(?:\[(?P<service>[^\]]+)\]\s+)?(?P<rest>.*)$", line)
    if m1:
        ts_s = m1.group('ts')
        level = m1.group('level')
        service = m1.group('service')
        rest = m1.group('rest') or ''
        kv, msg = _parse_kv(rest)
        ts = None
        try:
            ts = datetime.strptime(ts_s, "%Y-%m-%d %H:%M:%S")
        except Exception:
            ts = None
        ev = Event(timestamp=ts, level=level, service=service, message=msg or rest, kv=kv, raw=line)
    else:
        # Format 2: ISO 8601
        m2 = re.match(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+(?P<level>[A-Z]+)\s+(?P<rest>.*)$", line)
        if m2:
            ts_s = m2.group('ts')
            level = m2.group('level')
            rest = m2.group('rest') or ''
            kv, msg = _parse_kv(rest)
            ts = None
            try:
                ts = datetime.strptime(ts_s, "%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                ts = None
            service = kv.get('service')
            if 'msg' in kv:
                msg = kv['msg']
            ev = Event(timestamp=ts, level=level, service=service, message=msg or rest, kv=kv, raw=line)
        else:
            ev = Event(timestamp=None, level=None, service=None, message=line, kv={}, raw=line)

    # Enrich with common fields
    # IP
    ip = ev.kv.get('ip') or ev.kv.get('src_ip') or ev.kv.get('client_ip')
    if not ip:
        m_ip = _IP_RE.search(ev.message)
        if m_ip:
            ip = m_ip.group(0)
    ev.ip = ip
    # User
    ev.user = ev.kv.get('user') or ev.kv.get('username')
    # Endpoint
    ev.endpoint = ev.kv.get('endpoint') or ev.kv.get('path') or ev.kv.get('url')
    # Status / filename / query
    ev.status = ev.kv.get('status') or ev.kv.get('code')
    ev.filename = ev.kv.get('file') or ev.kv.get('filename')
    ev.query = ev.kv.get('q') or ev.kv.get('query') or ev.kv.get('payload') or ev.kv.get('params')

    return ev


def normalize_event(event: Event) -> Event:
    text = f"{event.level or ''} {event.service or ''} {event.message}".lower()
    PRIORITY = [
        'privilege_change', 'account_lockout', 'waf_sqli', 'waf_xss', 'waf_traversal',
        'file_upload_blocked', 'port_scan', 'auth_fail', 'auth_success', 'sudo_exec', 'app_error'
    ]

    def prio_of(t: str) -> int:
        try:
            return PRIORITY.index(t)
        except ValueError:
            return len(PRIORITY)

    current_type = event.event_type or 'unknown'
    current_prio = prio_of(current_type)

    # Deterministic scan by priority order
    for etype in PRIORITY:
        for p in CONFIG['event_type_patterns'].get(etype, []):
            if re.search(p, text, re.IGNORECASE):
                if current_type == 'unknown' or prio_of(etype) < current_prio:
                    current_type = etype
                    current_prio = prio_of(etype)
                break

    # Fallback via log level
    if (event.level and event.level.upper() == 'ERROR') and (current_type == 'unknown' or prio_of('app_error') < current_prio):
        current_type = 'app_error'

    event.event_type = current_type if current_type else 'unknown'
    return event


def _severity_from_score(score: int) -> str:
    if score >= 90:
        return 'critical'
    if score >= 60:
        return 'high'
    if score >= 30:
        return 'medium'
    return 'low'


def _is_allowlisted(event: Event) -> bool:
    if event.ip and event.ip in CONFIG['allowlists']['ips']:
        return True
    if event.endpoint and event.endpoint in CONFIG['allowlists']['endpoints']:
        return True
    if CONFIG['allowlists'].get('allow_internal') and event.ip:
        try:
            ipa = ip_address(event.ip)
            for cidr in CONFIG['allowlists']['internal_cidrs']:
                if ipa in ip_network(cidr):
                    return True
        except Exception:
            pass
    return False


def analyze_log_content(content: str) -> List[Dict]:
    """Analyze logs with event normalization, atomic + correlation rules, and risk scoring.

    Returns list[dict] where each finding includes: rule_name, description, severity, matched_lines, risk_score, confidence
    """
    debug_errors: List[str] = []

    # Parse lines into events
    raw_lines = [ln for ln in content.split('\n') if ln.strip()]
    events: List[Event] = []
    for ln in raw_lines:
        try:
            ev = parse_line(ln)
            ev = normalize_event(ev)
            events.append(ev)
        except Exception as e:
            if CONFIG['debug']:
                debug_errors.append(f"parse_normalize_error: {e} :: {ln[:200]}")
            events.append(Event(timestamp=None, level=None, service=None, message=ln, kv={}, raw=ln, event_type='unknown'))

    # Containers for risk and matched lines per entity
    risk_by_ip: Dict[str, int] = defaultdict(int)
    risk_by_user: Dict[str, int] = defaultdict(int)
    matched_by_rule: Dict[str, List[str]] = defaultdict(list)
    matched_by_rule_ip: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
    matched_by_rule_user: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))

    findings: List[Finding] = []

    # Atomic rules scoring
    for ev in events:
        if _is_allowlisted(ev):
            continue

        et = ev.event_type
        score_add = CONFIG['scoring'].get(et)
        if score_add:
            if ev.ip:
                risk_by_ip[ev.ip] += score_add
            if ev.user:
                risk_by_user[ev.user] += score_add

        # Keep compatibility rule names and matched lines
        line = ev.raw.strip()[:200]
        if et == 'auth_fail':
            if len(matched_by_rule['Upprepade misslyckade inloggningar']) < 5:
                matched_by_rule['Upprepade misslyckade inloggningar'].append(line)
            if ev.ip and len(matched_by_rule_ip['Upprepade misslyckade inloggningar'][ev.ip]) < 5:
                matched_by_rule_ip['Upprepade misslyckade inloggningar'][ev.ip].append(line)
            if ev.user and len(matched_by_rule_user['Upprepade misslyckade inloggningar'][ev.user]) < 5:
                matched_by_rule_user['Upprepade misslyckade inloggningar'][ev.user].append(line)
        if (ev.service and re.search(r'ssh', ev.service, re.IGNORECASE)) or 'sshd' in ev.raw.lower():
            if et == 'auth_fail':
                if len(matched_by_rule['SSH autentiseringsfel']) < 5:
                    matched_by_rule['SSH autentiseringsfel'].append(line)
        if et == 'sudo_exec' or (re.search(r'\bsudo\b', ev.raw, re.IGNORECASE) and 'sudo:' in ev.raw.lower()):
            if len(matched_by_rule['Sudo-kommandokörning']) < 5:
                matched_by_rule['Sudo-kommandokörning'].append(line)
        if re.search(r'useradd\b|userdel\b|usermod\b|passwd\b|groupadd\b|lägg till användare|ny användare|skapa användar|ta bort användar|ändra användar', ev.raw, re.IGNORECASE):
            if len(matched_by_rule['Ändringar av användarkonton']) < 5:
                matched_by_rule['Ändringar av användarkonton'].append(line)
        if et in ('waf_sqli', 'waf_xss', 'waf_traversal') and ev.ip:
            if len(matched_by_rule['Misstänkta IP-adresser']) < 5:
                matched_by_rule['Misstänkta IP-adresser'].append(line)
            if len(matched_by_rule_ip['Misstänkta IP-adresser'][ev.ip]) < 5:
                matched_by_rule_ip['Misstänkta IP-adresser'][ev.ip].append(line)
            if len(matched_by_rule_ip['WAF indikatorer'][ev.ip]) < 5:
                matched_by_rule_ip['WAF indikatorer'][ev.ip].append(line)
        if et == 'port_scan':
            if len(matched_by_rule['Brute-force-indikationer']) < 5:
                matched_by_rule['Brute-force-indikationer'].append(line)
            if ev.ip and len(matched_by_rule_ip['Brute-force-indikationer'][ev.ip]) < 5:
                matched_by_rule_ip['Brute-force-indikationer'][ev.ip].append(line)
        if et == 'privilege_change':
            if len(matched_by_rule['Privilege Escalation Attempts']) < 5:
                matched_by_rule['Privilege Escalation Attempts'].append(line)
        if et == 'app_error':
            if len(matched_by_rule['File Access Anomalies']) < 5 and re.search(r'permission denied|access denied|unauthorized|operation not permitted|read-only', ev.raw, re.IGNORECASE):
                matched_by_rule['File Access Anomalies'].append(line)
        # Suspicious IP keywords (compatibility with previous rule)
        if ev.ip:
            if re.search(r'attack|breach|exploit|payload|shellcode|injection|malware', ev.raw, re.IGNORECASE):
                if len(matched_by_rule['Misstänkta IP-adresser']) < 5:
                    matched_by_rule['Misstänkta IP-adresser'].append(line)
                if len(matched_by_rule_ip['Misstänkta IP-adresser'][ev.ip]) < 5:
                    matched_by_rule_ip['Misstänkta IP-adresser'][ev.ip].append(line)
        # Suspicious/blocked file uploads per IP
        if et == 'file_upload_blocked' and ev.ip:
            if len(matched_by_rule_ip['Otillåten filuppladdning'][ev.ip]) < 5:
                matched_by_rule_ip['Otillåten filuppladdning'][ev.ip].append(line)

    # Correlation windows by ip and user
    by_ip: Dict[str, List[Event]] = defaultdict(list)
    by_user: Dict[str, List[Event]] = defaultdict(list)
    for ev in events:
        if ev.ip:
            by_ip[ev.ip].append(ev)
        if ev.user:
            by_user[ev.user].append(ev)

    # Helper: events within window
    def in_window(evts: List[Event], center_ts: datetime, window_sec: int) -> List[Event]:
        start = center_ts - timedelta(seconds=window_sec)
        end = center_ts + timedelta(seconds=window_sec)
        return [e for e in evts if e.timestamp and start <= e.timestamp <= end]

    # Brute force per IP
    try:
        dedup = set()
        for ip, evts in by_ip.items():
            # sort by ts or keep order
            evts_sorted = sorted([e for e in evts if e.timestamp], key=lambda x: x.timestamp) or evts
            fails: deque = deque()
            count_peak = 0
            window = CONFIG['thresholds']['brute_force_window_sec']
            for e in evts_sorted:
                if e.event_type == 'auth_fail' and e.timestamp:
                    fails.append(e)
                    # purge
                    while fails and (e.timestamp - fails[0].timestamp).total_seconds() > window:
                        fails.popleft()
                    count_peak = max(count_peak, len(fails))
            if count_peak >= CONFIG['thresholds']['brute_force_count']:
                add = CONFIG['scoring']['brute_force']
                risk_by_ip[ip] += add
                key = ('Brute-force-indikationer', 'ip', ip)
                if key not in dedup:
                    dedup.add(key)
                    findings.append(Finding(
                        rule_name='Brute-force-indikationer',
                        description=f"Brute-force suspected from IP {ip}: {count_peak} failures within 5 min",
                        severity=_severity_from_score(risk_by_ip[ip]),
                        matched_lines=matched_by_rule_ip.get('Upprepade misslyckade inloggningar', {}).get(ip, [])[:5],
                        risk_score=risk_by_ip[ip],
                        confidence=0.8,
                    ))
    except Exception as e:
        if CONFIG['debug']:
            debug_errors.append(f"brute_force_rule_error: {e}")

    # Password spraying per IP (many users)
    try:
        for ip, evts in by_ip.items():
            evts_sorted = sorted([e for e in evts if e.timestamp], key=lambda x: x.timestamp) or evts
            window = CONFIG['thresholds']['spray_window_sec']
            for i, e in enumerate(evts_sorted):
                if e.event_type == 'auth_fail' and e.timestamp:
                    win = in_window(evts_sorted, e.timestamp, window)
                    users = {w.user for w in win if w.event_type == 'auth_fail' and w.user}
                    if len(users) >= CONFIG['thresholds']['spray_unique_users']:
                        risk_by_ip[ip] += CONFIG['scoring']['password_spraying']
                        key = ('Password spraying', 'ip', ip)
                        if key not in dedup:
                            dedup.add(key)
                            findings.append(Finding(
                                rule_name='Upprepade misslyckade inloggningar',
                                description=f"Password spraying suspected from IP {ip}: {len(users)} users within 10 min",
                                severity=_severity_from_score(risk_by_ip[ip]),
                                matched_lines=matched_by_rule_ip.get('Upprepade misslyckade inloggningar', {}).get(ip, [])[:5],
                                risk_score=risk_by_ip[ip],
                                confidence=0.75,
                            ))
                        break
    except Exception as e:
        if CONFIG['debug']:
            debug_errors.append(f"password_spraying_rule_error: {e}")

    # Failures then success for same ip or user
    def _fail_then_success(evts: List[Event], label: str):
        evts_sorted = sorted([e for e in evts if e.timestamp], key=lambda x: x.timestamp) or evts
        window = CONFIG['thresholds']['fail_then_success_window_sec']
        for i in range(len(evts_sorted)):
            e = evts_sorted[i]
            if e.event_type == 'auth_success' and e.timestamp:
                within = in_window(evts_sorted, e.timestamp, window)
                fails_count = sum(1 for w in within if w.event_type == 'auth_fail' and w.timestamp and w.timestamp <= e.timestamp)
                if fails_count >= 3:
                    return True, fails_count, e
        return False, 0, None

    try:
        for ip, evts in by_ip.items():
            ok, n, succ = _fail_then_success(evts, ip)
            if ok:
                risk_by_ip[ip] += CONFIG['scoring']['fail_then_success']
                key = ('FailThenSuccess', 'ip', ip)
                if key not in dedup:
                    dedup.add(key)
                    findings.append(Finding(
                        rule_name='Upprepade misslyckade inloggningar',
                        description=f"Failures followed by success for IP {ip}: {n} failures then success within 10 min",
                        severity=_severity_from_score(risk_by_ip[ip]),
                        matched_lines=matched_by_rule_ip.get('Upprepade misslyckade inloggningar', {}).get(ip, [])[:5],
                        risk_score=risk_by_ip[ip],
                        confidence=0.85,
                    ))
    except Exception as e:
        if CONFIG['debug']:
            debug_errors.append(f"fail_then_success_ip_rule_error: {e}")

    try:
        for user, evts in by_user.items():
            ok, n, succ = _fail_then_success(evts, user)
            if ok:
                risk_by_user[user] += CONFIG['scoring']['fail_then_success']
                key = ('FailThenSuccess', 'user', user)
                if key not in dedup:
                    dedup.add(key)
                    findings.append(Finding(
                        rule_name='Upprepade misslyckade inloggningar',
                        description=f"Failures followed by success for user {user}: {n} failures then success within 10 min",
                        severity=_severity_from_score(risk_by_user[user]),
                        matched_lines=matched_by_rule_user.get('Upprepade misslyckade inloggningar', {}).get(user, [])[:5],
                        risk_score=risk_by_user[user],
                        confidence=0.85,
                    ))
    except Exception as e:
        if CONFIG['debug']:
            debug_errors.append(f"fail_then_success_user_rule_error: {e}")

    # WAF + auth correlation per IP
    try:
        for ip, evts in by_ip.items():
            evts_sorted = sorted([e for e in evts if e.timestamp], key=lambda x: x.timestamp) or evts
            window = CONFIG['thresholds']['waf_plus_auth_window_sec']
            waf_types = {'waf_sqli', 'waf_xss', 'waf_traversal'}
            for e in evts_sorted:
                if e.timestamp and e.event_type in waf_types:
                    within = in_window(evts_sorted, e.timestamp, window)
                    if any(w.event_type == 'auth_fail' for w in within):
                        risk_by_ip[ip] += CONFIG['scoring']['waf_plus_auth']
                        key = ('WAF+AUTH', 'ip', ip)
                        if key not in dedup:
                            dedup.add(key)
                            lines = matched_by_rule_ip.get('Misstänkta IP-adresser', {}).get(ip, [])
                            if not lines:
                                lines = matched_by_rule_ip.get('Upprepade misslyckade inloggningar', {}).get(ip, [])
                            score = max(risk_by_ip[ip], 95)
                            findings.append(Finding(
                                rule_name='Misstänkta IP-adresser',
                                description=f"WAF indicators plus auth failures from IP {ip} within 10 min",
                                severity='critical',
                                matched_lines=lines[:5],
                                risk_score=score,
                                confidence=0.7,
                            ))
                        break
    except Exception as e:
        if CONFIG['debug']:
            debug_errors.append(f"waf_plus_auth_rule_error: {e}")

    # Port scan correlation (many different ports)
    try:
        ip_port_re = re.compile(r"\b((?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}):(\d{1,5})\b")
        for ip, evts in by_ip.items():
            ports = set()
            evidence: List[str] = []
            for e in evts:
                # KV fields
                for k in ('dest_port', 'src_port', 'port'):
                    if k in e.kv and e.kv[k].isdigit():
                        p = int(e.kv[k])
                        if 1 <= p <= 65535:
                            ports.add(p)
                            if len(evidence) < 5:
                                evidence.append(e.raw[:200])
                # ports list: ports=22,80,443
                if 'ports' in e.kv:
                    for seg in re.split(r'[;,\s]+', e.kv['ports']):
                        if seg.isdigit():
                            p = int(seg)
                            if 1 <= p <= 65535:
                                ports.add(p)
                                if len(evidence) < 5:
                                    evidence.append(e.raw[:200])
                # ip:port occurrences only
                for m in ip_port_re.finditer(e.raw):
                    p = int(m.group(2))
                    if 1 <= p <= 65535:
                        ports.add(p)
                        if len(evidence) < 5:
                            evidence.append(e.raw[:200])
            if len(ports) >= CONFIG['thresholds']['port_scan_unique_ports']:
                risk_by_ip[ip] += CONFIG['scoring']['multi_port_scan']
                key = ('PortScan', 'ip', ip)
                if key not in dedup:
                    dedup.add(key)
                    # Store evidence per IP bucket too
                    for evl in evidence:
                        if len(matched_by_rule_ip['Brute-force-indikationer'][ip]) < 5:
                            matched_by_rule_ip['Brute-force-indikationer'][ip].append(evl)
                    findings.append(Finding(
                        rule_name='Brute-force-indikationer',
                        description=f"Port scanning suspected from IP {ip}: {len(ports)} unique ports",
                        severity=_severity_from_score(risk_by_ip[ip]),
                        matched_lines=matched_by_rule_ip.get('Brute-force-indikationer', {}).get(ip, [])[:5],
                        risk_score=risk_by_ip[ip],
                        confidence=0.7,
                    ))
    except Exception as e:
        if CONFIG['debug']:
            debug_errors.append(f"port_scan_rule_error: {e}")

    # Compatibility/summary findings for some atomics
    # Aggregate failed login attempts across entire file (no timestamp fallback)
    total_auth_fails = sum(1 for e in events if e.event_type == 'auth_fail')
    if total_auth_fails > 5:
        base = 30 if total_auth_fails <= 20 else 60
        findings.append(Finding(
            rule_name='Upprepade misslyckade inloggningar',
            description=f"Detected {total_auth_fails} failed login attempts",
            severity=_severity_from_score(base),
            matched_lines=matched_by_rule.get('Upprepade misslyckade inloggningar', [])[:5],
            risk_score=base,
            confidence=0.7,
        ))

    # Heuristic brute-force indicators without timestamps
    brute_patterns = [r'Connection attempt', r'Connection refused', r'Connection reset', r'Port scan', r'Too many authentication', r'Rate limit']
    brute_count = 0
    brute_lines: List[str] = []
    for e in events:
        if any(re.search(p, e.raw, re.IGNORECASE) for p in brute_patterns):
            brute_count += 1
            if len(brute_lines) < 5:
                brute_lines.append(e.raw[:200])
    if brute_count > 10:
        score = 50 if brute_count < 30 else 70
        findings.append(Finding(
            rule_name='Brute-force-indikationer',
            description=f"Detected {brute_count} connection attempts/anomalies",
            severity=_severity_from_score(score),
            matched_lines=brute_lines,
            risk_score=score,
            confidence=0.65,
        ))
    # SSH auth failures
    if matched_by_rule.get('SSH autentiseringsfel'):
        score = 30 + min(20, 2 * len(matched_by_rule['SSH autentiseringsfel']))
        findings.append(Finding(
            rule_name='SSH autentiseringsfel',
            description=f"Detected {len(matched_by_rule['SSH autentiseringsfel'])} SSH authentication failures",
            severity=_severity_from_score(score),
            matched_lines=matched_by_rule['SSH autentiseringsfel'][:5],
            risk_score=score,
            confidence=0.7,
        ))

    # Sudo usage
    if matched_by_rule.get('Sudo-kommandokörning'):
        score = 10 + 3 * len(matched_by_rule['Sudo-kommandokörning'])
        findings.append(Finding(
            rule_name='Sudo-kommandokörning',
            description=f"Detected {len(matched_by_rule['Sudo-kommandokörning'])} sudo executions",
            severity=_severity_from_score(score),
            matched_lines=matched_by_rule['Sudo-kommandokörning'][:5],
            risk_score=score,
            confidence=0.6,
        ))

    # User account changes
    if matched_by_rule.get('Ändringar av användarkonton'):
        score = 25 + 2 * len(matched_by_rule['Ändringar av användarkonton'])
        findings.append(Finding(
            rule_name='Ändringar av användarkonton',
            description=f"Detected {len(matched_by_rule['Ändringar av användarkonton'])} user account modifications",
            severity=_severity_from_score(score),
            matched_lines=matched_by_rule['Ändringar av användarkonton'][:5],
            risk_score=score,
            confidence=0.65,
        ))

    # Privilege escalation attempts
    if matched_by_rule.get('Privilege Escalation Attempts'):
        score = 70
        findings.append(Finding(
            rule_name='Privilege Escalation Attempts',
            description=f"Potential privilege escalation attempts detected",
            severity=_severity_from_score(score),
            matched_lines=matched_by_rule['Privilege Escalation Attempts'][:5],
            risk_score=score,
            confidence=0.7,
        ))

    # File access anomalies (from app errors indicating permission issues)
    if matched_by_rule.get('File Access Anomalies'):
        score = 15
        findings.append(Finding(
            rule_name='File Access Anomalies',
            description=f"Multiple file access anomalies detected",
            severity=_severity_from_score(score),
            matched_lines=matched_by_rule['File Access Anomalies'][:5],
            risk_score=score,
            confidence=0.5,
        ))

    # Per-IP WAF indicator findings (HIGH)
    if matched_by_rule_ip.get('WAF indikatorer'):
        for ip, lines in matched_by_rule_ip['WAF indikatorer'].items():
            score = max(60, risk_by_ip.get(ip, 0))
            findings.append(Finding(
                rule_name='Misstänkta IP-adresser',
                description=f"WAF indicators detected from IP {ip}",
                severity=_severity_from_score(score),
                matched_lines=lines[:5],
                risk_score=score,
                confidence=0.7,
            ))

    # Per-IP suspicious IP activity (HIGH)
    if matched_by_rule_ip.get('Misstänkta IP-adresser'):
        for ip, lines in matched_by_rule_ip['Misstänkta IP-adresser'].items():
            score = max(60, risk_by_ip.get(ip, 0))
            findings.append(Finding(
                rule_name='Misstänkta IP-adresser',
                description=f"Suspicious IP activity detected for IP {ip}",
                severity=_severity_from_score(score),
                matched_lines=lines[:5],
                risk_score=score,
                confidence=0.65,
            ))

    # Per-IP blocked file uploads (HIGH)
    if matched_by_rule_ip.get('Otillåten filuppladdning'):
        for ip, lines in matched_by_rule_ip['Otillåten filuppladdning'].items():
            score = max(60, risk_by_ip.get(ip, 0))
            findings.append(Finding(
                rule_name='Otillåten filuppladdning',
                description=f"Blocked or suspicious file upload from IP {ip}",
                severity=_severity_from_score(score),
                matched_lines=lines[:5],
                risk_score=score,
                confidence=0.75,
            ))

    # Hard triggers: privilege change to admin/root
    for ev in events:
        if ev.event_type == 'privilege_change' and re.search(r'\b(root|admin)\b', ev.raw, re.IGNORECASE):
            score = 95
            findings.append(Finding(
                rule_name='Privilege Escalation Attempts',
                description='Privilege change to admin/root detected',
                severity=_severity_from_score(score),
                matched_lines=[ev.raw[:200]],
                risk_score=score,
                confidence=0.9,
            ))

    # Sort by severity then risk_score desc
    # Deduplicate findings by (rule_name, entity) while keeping highest severity/risk and merging lines
    def _entity_from_desc_or_lines(desc: str, lines: List[str]) -> Tuple[Optional[str], Optional[str]]:
        m = re.search(r"\bIP\s+(\d+\.\d+\.\d+\.\d+)\b", desc, re.IGNORECASE)
        if m:
            return 'ip', m.group(1)
        m = re.search(r"\buser\s+([^\s:]+)\b", desc, re.IGNORECASE)
        if m:
            return 'user', m.group(1)
        # Try extract IP from matched_lines if present
        for ln in lines or []:
            mi = _IP_RE.search(ln)
            if mi:
                return 'ip', mi.group(0)
        return None, None

    def _is_summary_find(rule: str, desc: str) -> bool:
        txt = desc.lower().strip()
        if re.match(r"^(detected|multiple|suspicious)", txt):
            return True
        # Rule-name based summaries
        if rule in {'SSH autentiseringsfel', 'Sudo-kommandokörning', 'Ändringar av användarkonton', 'File Access Anomalies', 'Misstänkta IP-adresser'}:
            return True
        return False

    sev_rank = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    best: Dict[Tuple[str, str, str], Finding] = {}
    for f in findings:
        etype, evalue = _entity_from_desc_or_lines(f.description, f.matched_lines)
        key = (f.rule_name.lower(), etype or '', evalue or '')
        if key not in best:
            best[key] = f
        else:
            cur = best[key]
            cur_is_summary = _is_summary_find(cur.rule_name, cur.description)
            new_is_summary = _is_summary_find(f.rule_name, f.description)

            def merge_lines(dst: Finding, src: Finding):
                seen = set(dst.matched_lines)
                for l in src.matched_lines:
                    if l not in seen and len(seen) < 5:
                        dst.matched_lines.append(l)
                        seen.add(l)

            # Prefer detailed over summary
            if cur_is_summary and not new_is_summary:
                merge_lines(f, cur)
                best[key] = f
            elif not cur_is_summary and new_is_summary:
                merge_lines(cur, f)
                best[key] = cur
            else:
                # Compare severity then score
                if (
                    sev_rank.get(f.severity, 9) < sev_rank.get(cur.severity, 9)
                    or (
                        sev_rank.get(f.severity, 9) == sev_rank.get(cur.severity, 9)
                        and f.risk_score > cur.risk_score
                    )
                ):
                    merge_lines(f, cur)
                    best[key] = f
                else:
                    merge_lines(cur, f)
                    best[key] = cur

    findings = list(best.values())

    # Special-case filter: for each IP, if a critical 'Misstänkta IP-adresser' exists,
    # drop the high-severity 'Misstänkta IP-adresser' for the same IP
    critical_ips = set()
    for f in findings:
        if f.rule_name == 'Misstänkta IP-adresser' and f.severity == 'critical':
            et, ev = _entity_from_desc_or_lines(f.description, f.matched_lines)
            if et == 'ip' and ev:
                critical_ips.add(ev)

    if critical_ips:
        filtered = []
        for f in findings:
            if f.rule_name == 'Misstänkta IP-adresser' and f.severity == 'high':
                et, ev = _entity_from_desc_or_lines(f.description, f.matched_lines)
                if et == 'ip' and ev in critical_ips:
                    # skip redundant high summary for same IP
                    continue
            filtered.append(f)
        findings = filtered

    order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    findings.sort(key=lambda f: (order.get(f.severity, 9), -f.risk_score))

    # Convert to dicts and escape (already escaped in to_safe_dict)
    out = [f.to_safe_dict() for f in findings]

    # Optional: include analyzer errors if debug
    if CONFIG['debug'] and debug_errors:
        out.append(Finding(
            rule_name='analyzer_error',
            description='; '.join(debug_errors)[:500],
            severity='low',
            matched_lines=[],
            risk_score=0,
            confidence=1.0,
        ).to_safe_dict())

    return out
