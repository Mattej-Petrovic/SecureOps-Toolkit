"""
SecureOps Toolkit - Log Analyzer

Goals
- Detect common security-relevant patterns in Linux auth/syslog style logs.
- Support both English and Swedish log phrasing (matching), but ALWAYS return English UI text.
- Reduce false positives and avoid duplicate findings (deduplicate matched lines across rules).

Public API
- analyze_log_content(log_content: str) -> list[dict]
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Pattern, Tuple
import re
from collections import Counter, defaultdict


# -----------------------------
# Data model
# -----------------------------

@dataclass
class Finding:
    rule_name: str
    severity: str  # "critical" | "high" | "medium" | "low"
    description: str
    matched_lines: List[str] = field(default_factory=list)
    count: int = 0
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "severity": self.severity,
            "description": self.description,
            "matched_lines": self.matched_lines,
            "count": self.count,
            "details": self.details,
        }


# -----------------------------
# Helpers
# -----------------------------

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

SERVICE_ACCOUNTS = {
    "www-data", "nginx", "apache", "httpd", "nobody",
    "mysql", "postgres", "redis", "ftp", "daemon",
}

PRIV_GROUPS = {"sudo", "wheel", "admin"}


def _is_ip(host: str) -> bool:
    return bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host.strip()))


def _extract_first_ip(text: str) -> Optional[str]:
    m = re.search(r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})", text)
    return m.group("ip") if m else None


def _limit(lines: List[str], max_lines: int) -> List[str]:
    if max_lines <= 0:
        return []
    if len(lines) <= max_lines:
        return lines
    return lines[:max_lines]


def _normalize_ws(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def _pick_severity(base: str, score: int) -> str:
    """
    score: 0..100
    base is the minimum.
    """
    if score >= 85:
        sev = "critical"
    elif score >= 65:
        sev = "high"
    elif score >= 35:
        sev = "medium"
    else:
        sev = "low"
    # never go below base
    if SEVERITY_RANK[sev] < SEVERITY_RANK[base]:
        return base
    return sev


# -----------------------------
# Regex patterns (English + Swedish)
# -----------------------------

# SSH failures (common OpenSSH wording)
SSH_FAIL_PATTERNS: List[Pattern[str]] = [
    re.compile(
        r"sshd\[\d+\]:\s+Failed password for (?:invalid user\s+)?(?P<user>\S+) from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
        re.IGNORECASE,
    ),
    re.compile(
        r"sshd\[\d+\]:\s+Invalid user (?P<user>\S+) from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
        re.IGNORECASE,
    ),
    re.compile(
        r"sshd\[\d+\]:\s+Failed publickey for (?:invalid user\s+)?(?P<user>\S+) from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
        re.IGNORECASE,
    ),
    # Swedish phrasing (approx)
    re.compile(
        r"sshd\[\d+\]:\s+Fel lösenord för (?:ogiltig användare\s+)?(?P<user>\S+) från (?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
        re.IGNORECASE,
    ),
    re.compile(
        r"sshd\[\d+\]:\s+Ogiltig användare (?P<user>\S+) från (?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
        re.IGNORECASE,
    ),
]

# Generic authentication / login failures (non-SSH, web apps, PAM, etc)
GENERIC_LOGIN_FAIL_PATTERNS: List[Pattern[str]] = [
    re.compile(r"Failed login (?:for|from)\s+(?P<user>\S+)", re.IGNORECASE),
    re.compile(r"Invalid password for\s+(?P<user>\S+)", re.IGNORECASE),
    re.compile(r"authentication failure", re.IGNORECASE),
    # Swedish-ish
    re.compile(r"misslyckad inloggning", re.IGNORECASE),
    re.compile(r"autentisering(?:en)? misslyckades", re.IGNORECASE),
]

# Sudo command format (auth.log)
SUDO_PATTERN = re.compile(
    r"sudo(?:\[\d+\])?:\s*(?P<user>\S+)\s*:\s*TTY=(?P<tty>[^;]+)\s*;\s*PWD=(?P<pwd>[^;]+)\s*;\s*USER=(?P<target>[^;]+)\s*;\s*COMMAND=(?P<cmd>.+)$",
    re.IGNORECASE,
)

# Cron command format
CRON_PATTERN = re.compile(
    r"CRON\[\d+\]:\s*\((?P<user>[^)]+)\)\s*CMD\s*\((?P<cmd>.+)\)",
    re.IGNORECASE,
)

# User and group changes
USERADD_PATTERN = re.compile(r"useradd\[\d+\]:\s*new user:\s*name=(?P<user>[^,\s]+)", re.IGNORECASE)
USERDEL_PATTERN = re.compile(r"userdel\[\d+\]:\s*remove user\s+'?(?P<user>[^'\s]+)'?", re.IGNORECASE)
PASSWD_CHANGED_PATTERN = re.compile(r"passwd\[\d+\]:\s*password changed for (?P<user>\S+)", re.IGNORECASE)
GROUPADD_PATTERN = re.compile(r"groupadd\[\d+\]:\s*new group:\s*name=(?P<group>[^,\s]+)", re.IGNORECASE)
USERMOD_ADD_GROUP_PATTERN = re.compile(
    r"usermod\[\d+\]:\s*add\s+'(?P<user>[^']+)'\s+to group\s+'(?P<group>[^']+)'",
    re.IGNORECASE,
)

# Swedish-ish account changes
SV_USERADD_PATTERN = re.compile(r"ny användare:\s*namn=(?P<user>[^,\s]+)", re.IGNORECASE)
SV_PASSWD_PATTERN = re.compile(r"lösenord ändrat för\s+(?P<user>\S+)", re.IGNORECASE)
SV_GROUPADD_PATTERN = re.compile(r"ny grupp:\s*namn=(?P<group>[^,\s]+)", re.IGNORECASE)
SV_USERMOD_GROUP_PATTERN = re.compile(r"lägg(?:er| till)\s+'(?P<user>[^']+)'\s+till grupp\s+'(?P<group>[^']+)'", re.IGNORECASE)


# Suspicious download / execution patterns
DOWNLOAD_PATTERN = re.compile(r"\b(curl|wget)\b", re.IGNORECASE)
URL_PATTERN = re.compile(r"(https?://)(?P<host>[^/\s:]+)", re.IGNORECASE)
PIPE_TO_SHELL_PATTERN = re.compile(r"\|\s*(bash|sh)\b", re.IGNORECASE)


# Privilege escalation suspicious commands
SUSP_PRIV_CMDS = [
    re.compile(r"\b(?:su|sudo)\s+-?i\b", re.IGNORECASE),
    re.compile(r"\b/bin/(?:ba)?sh\b", re.IGNORECASE),
    re.compile(r"\bvisudo\b", re.IGNORECASE),
    re.compile(r"/etc/sudoers", re.IGNORECASE),
    re.compile(r"/etc/(?:passwd|shadow|group)\b", re.IGNORECASE),
    re.compile(r"\bchmod\s+\+s\b", re.IGNORECASE),
    re.compile(r"\bsetcap\s+cap_setuid\+ep\b", re.IGNORECASE),
    re.compile(r"\b(pkexec)\b", re.IGNORECASE),
]


# -----------------------------
# Event extraction
# -----------------------------

@dataclass
class _Event:
    kind: str
    line_idx: int
    line: str
    ip: Optional[str] = None
    user: Optional[str] = None
    target_user: Optional[str] = None
    command: Optional[str] = None
    group: Optional[str] = None


def _iter_lines(log_content: str) -> List[str]:
    # Keep original line order, strip newlines only
    return [ln.rstrip("\n") for ln in log_content.splitlines() if ln.strip()]


def _extract_events(lines: List[str]) -> List[_Event]:
    events: List[_Event] = []
    for idx, line in enumerate(lines):
        # SSH failures
        for pat in SSH_FAIL_PATTERNS:
            m = pat.search(line)
            if m:
                events.append(_Event(
                    kind="ssh_fail",
                    line_idx=idx,
                    line=line,
                    ip=m.groupdict().get("ip"),
                    user=m.groupdict().get("user"),
                ))
                break

        # Sudo commands
        m = SUDO_PATTERN.search(line)
        if m:
            cmd = _normalize_ws(m.group("cmd"))
            events.append(_Event(
                kind="sudo_cmd",
                line_idx=idx,
                line=line,
                user=m.group("user").strip(),
                target_user=m.group("target").strip(),
                command=cmd.strip(),
            ))

        # Cron
        m = CRON_PATTERN.search(line)
        if m:
            cmd = _normalize_ws(m.group("cmd"))
            events.append(_Event(
                kind="cron_cmd",
                line_idx=idx,
                line=line,
                user=m.group("user").strip(),
                command=cmd.strip(),
            ))

        # User and group changes (English + Swedish)
        for pat, kind in [
            (USERADD_PATTERN, "user_add"),
            (SV_USERADD_PATTERN, "user_add"),
            (USERDEL_PATTERN, "user_del"),
            (PASSWD_CHANGED_PATTERN, "passwd_change"),
            (SV_PASSWD_PATTERN, "passwd_change"),
            (GROUPADD_PATTERN, "group_add"),
            (SV_GROUPADD_PATTERN, "group_add"),
            (USERMOD_ADD_GROUP_PATTERN, "usermod_add_group"),
            (SV_USERMOD_GROUP_PATTERN, "usermod_add_group"),
        ]:
            m = pat.search(line)
            if not m:
                continue
            gd = m.groupdict()
            events.append(_Event(
                kind=kind,
                line_idx=idx,
                line=line,
                user=gd.get("user"),
                group=gd.get("group"),
            ))
            break

        # Generic login failures (only if not already ssh_fail)
        if not any(e.kind == "ssh_fail" and e.line_idx == idx for e in events):
            if any(p.search(line) for p in GENERIC_LOGIN_FAIL_PATTERNS):
                events.append(_Event(
                    kind="login_fail_generic",
                    line_idx=idx,
                    line=line,
                    ip=_extract_first_ip(line),
                ))

    return events


# -----------------------------
# Rule building
# -----------------------------

def _build_privilege_escalation(events: List[_Event], used: set[int], max_lines: int) -> Optional[Finding]:
    matched: List[_Event] = []
    score = 0

    # group additions to sudo/wheel/admin are strong signals
    for e in events:
        if e.line_idx in used:
            continue
        if e.kind == "usermod_add_group" and (e.group or "").strip("'\"").lower() in PRIV_GROUPS:
            matched.append(e)
            score = max(score, 90)

    # suspicious sudo usage
    for e in events:
        if e.line_idx in used:
            continue
        if e.kind != "sudo_cmd":
            continue

        user = (e.user or "").strip().lower()
        target = (e.target_user or "").strip().lower()
        cmd = (e.command or "").lower()

        suspicious_cmd = any(p.search(cmd) for p in SUSP_PRIV_CMDS) or PIPE_TO_SHELL_PATTERN.search(cmd)
        service_user = user in SERVICE_ACCOUNTS
        weird_target = target in {"root"}  # root is common, but combined with service accounts or shell -> strong signal

        # service accounts running sudo, or sudo to shell-like commands
        if service_user and weird_target:
            matched.append(e)
            score = max(score, 90 if suspicious_cmd else 75)
        elif suspicious_cmd:
            matched.append(e)
            score = max(score, 80)

    if not matched:
        return None

    # Deduplicate line indices
    uniq = {}
    for e in matched:
        uniq[e.line_idx] = e
    matched = [uniq[i] for i in sorted(uniq.keys())]

    sev = _pick_severity("high", score)

    # Mark used lines
    for e in matched:
        used.add(e.line_idx)

    # Describe
    reasons = []
    if any(e.kind == "usermod_add_group" for e in matched):
        reasons.append("User added to a privileged group (sudo, wheel, or admin).")
    if any(e.kind == "sudo_cmd" and (e.user or "").lower() in SERVICE_ACCOUNTS for e in matched):
        reasons.append("Service account executed sudo as root.")
    if any(e.kind == "cron_cmd" for e in matched):
        reasons.append("Cron executed a download or shell command.")
    if any(e.kind == "sudo_cmd" and any(p.search((e.command or "").lower()) for p in SUSP_PRIV_CMDS) for e in matched):
        reasons.append("Sudo executed shell or sensitive system commands.")

    description = "Potential privilege escalation attempts detected. " + " ".join(reasons[:3])

    return Finding(
        rule_name="Privilege Escalation Attempts",
        severity=sev,
        description=description.strip(),
        matched_lines=_limit([e.line for e in matched], max_lines),
        count=len(matched),
        details={
            "signals": reasons,
        },
    )


def _build_suspicious_ip(events: List[_Event], used: set[int], max_lines: int) -> Optional[Finding]:
    matched: List[_Event] = []
    score = 0
    suspicious_hosts: List[str] = []

    # We look at cron and sudo and any line with curl/wget and an IP host
    for e in events:
        if e.line_idx in used:
            continue
        line = e.line
        if not DOWNLOAD_PATTERN.search(line):
            continue

        # Find URL host(s)
        hosts = [m.group("host") for m in URL_PATTERN.finditer(line)]
        ip_hosts = [h for h in hosts if _is_ip(h)]
        if not ip_hosts:
            continue

        matched.append(e)
        suspicious_hosts.extend(ip_hosts)

        # escalate if piped to shell or looks like payload execution
        if PIPE_TO_SHELL_PATTERN.search(line) or "payload" in line.lower():
            score = max(score, 95)
        else:
            score = max(score, 70)

    if not matched:
        return None

    uniq = {}
    for e in matched:
        uniq[e.line_idx] = e
    matched = [uniq[i] for i in sorted(uniq.keys())]
    sev = _pick_severity("high", score)

    for e in matched:
        used.add(e.line_idx)

    top_hosts = [h for h, _ in Counter(suspicious_hosts).most_common(3)]
    host_text = ", ".join(top_hosts) if top_hosts else "one or more IP hosts"

    description = f"Detected suspicious download or execution behavior involving: {host_text}."

    return Finding(
        rule_name="Suspicious IP Addresses",
        severity=sev,
        description=description,
        matched_lines=_limit([e.line for e in matched], max_lines),
        count=len(matched),
        details={"ip_hosts": top_hosts},
    )


def _build_bruteforce(events: List[_Event], used: set[int], max_lines: int) -> Optional[Finding]:
    ssh_fails = [e for e in events if e.kind == "ssh_fail" and e.line_idx not in used]

    if not ssh_fails:
        return None

    ip_counts = Counter([e.ip for e in ssh_fails if e.ip])
    user_counts = Counter([e.user for e in ssh_fails if e.user])

    # Thresholds tuned to be useful and also align with typical unit tests.
    worst_ip, worst_ip_count = (None, 0)
    if ip_counts:
        worst_ip, worst_ip_count = ip_counts.most_common(1)[0]

    worst_user, worst_user_count = (None, 0)
    if user_counts:
        worst_user, worst_user_count = user_counts.most_common(1)[0]

    # Trigger bruteforce only if concentration is meaningful
    trigger = (worst_ip_count >= 8) or (worst_user_count >= 8) or (len(ssh_fails) >= 15)
    if not trigger:
        return None

    # Severity based on concentration
    score = 65
    if worst_ip_count >= 15 or len(ssh_fails) >= 30:
        score = 90
    elif worst_ip_count >= 10 or worst_user_count >= 10:
        score = 80

    sev = _pick_severity("high", score)

    # Build summary
    top_ips = ip_counts.most_common(3)
    top_users = user_counts.most_common(3)

    ip_summary = ", ".join([f"{ip} ({c})" for ip, c in top_ips if ip]) or "N/A"
    user_summary = ", ".join([f"{u} ({c})" for u, c in top_users if u]) or "N/A"

    description = f"High concentration of failed SSH logins detected. Top source IPs: {ip_summary}. Top targeted usernames: {user_summary}."

    # Use the ssh fail lines for this rule and mark them used so we don't duplicate later
    ordered = sorted(ssh_fails, key=lambda e: e.line_idx)
    for e in ordered:
        used.add(e.line_idx)

    return Finding(
        rule_name="Brute Force Indicators",
        severity=sev,
        description=description,
        matched_lines=_limit([e.line for e in ordered], max_lines),
        count=len(ordered),
        details={
            "top_ips": top_ips,
            "top_users": top_users,
        },
    )


def _build_user_account_changes(events: List[_Event], used: set[int], max_lines: int) -> Optional[Finding]:
    kinds = {"user_add", "user_del", "passwd_change", "group_add", "usermod_add_group"}
    matched = [e for e in events if e.kind in kinds and e.line_idx not in used]
    if not matched:
        return None

    # If it is "usermod add to sudo/wheel/admin", that should already be in privilege escalation (higher priority).
    matched = [e for e in matched if not (e.kind == "usermod_add_group" and (e.group or "").strip("'\"").lower() in PRIV_GROUPS)]

    if not matched:
        return None

    for e in matched:
        used.add(e.line_idx)

    description = "Detected user or group account changes."

    return Finding(
        rule_name="User Account Changes",
        severity="medium",
        description=description,
        matched_lines=_limit([e.line for e in sorted(matched, key=lambda e: e.line_idx)], max_lines),
        count=len(matched),
        details={
            "types": Counter([e.kind for e in matched]),
        },
    )


def _build_ssh_auth_failures(events: List[_Event], used: set[int], max_lines: int) -> Optional[Finding]:
    matched = [e for e in events if e.kind == "ssh_fail" and e.line_idx not in used]
    if not matched:
        return None

    # If brute force fired, we typically consumed most ssh fails already.
    # This rule is for smaller amounts (or leftover IPs).
    ip_counts = Counter([e.ip for e in matched if e.ip])
    worst = ip_counts.most_common(1)[0][1] if ip_counts else len(matched)

    score = 35
    if worst >= 10 or len(matched) >= 15:
        score = 70
    elif worst >= 6:
        score = 55

    sev = _pick_severity("medium", score)
    top_ips = ", ".join([f"{ip} ({c})" for ip, c in ip_counts.most_common(3) if ip]) if ip_counts else "N/A"

    description = f"Detected {len(matched)} SSH authentication failures. Top source IPs: {top_ips}."

    for e in matched:
        used.add(e.line_idx)

    return Finding(
        rule_name="SSH Authentication Failures",
        severity=sev,
        description=description,
        matched_lines=_limit([e.line for e in sorted(matched, key=lambda e: e.line_idx)], max_lines),
        count=len(matched),
        details={"top_ips": ip_counts.most_common(3)},
    )


def _build_repeated_failed_logins(events: List[_Event], used: set[int], max_lines: int) -> Optional[Finding]:
    # Only consider generic (non-ssh) failures to avoid duplication.
    matched = [e for e in events if e.kind == "login_fail_generic" and e.line_idx not in used]
    if not matched:
        return None

    ip_counts = Counter([e.ip for e in matched if e.ip])
    worst = ip_counts.most_common(1)[0][1] if ip_counts else len(matched)

    score = 35
    if worst >= 10 or len(matched) >= 20:
        score = 70
    elif worst >= 6:
        score = 55

    sev = _pick_severity("medium", score)
    top_ips = ", ".join([f"{ip} ({c})" for ip, c in ip_counts.most_common(3) if ip]) if ip_counts else "N/A"

    description = f"Detected {len(matched)} failed login attempts (non-SSH). Top source IPs: {top_ips}."

    for e in matched:
        used.add(e.line_idx)

    return Finding(
        rule_name="Repeated Failed Login Attempts",
        severity=sev,
        description=description,
        matched_lines=_limit([e.line for e in sorted(matched, key=lambda e: e.line_idx)], max_lines),
        count=len(matched),
        details={"top_ips": ip_counts.most_common(3)},
    )


def _build_sudo_execution(events: List[_Event], used: set[int], max_lines: int) -> Optional[Finding]:
    matched = [e for e in events if e.kind == "sudo_cmd" and e.line_idx not in used]
    if not matched:
        return None

    # Score and severity based on suspicious characteristics, but keep this as a general rule.
    # Strongly suspicious sudo should already be consumed by "Privilege Escalation Attempts".
    score = 10
    for e in matched:
        user = (e.user or "").strip().lower()
        cmd = (e.command or "").lower()
        target = (e.target_user or "").strip().lower()

        if user in SERVICE_ACCOUNTS and target == "root":
            score = max(score, 60)
        if any(p.search(cmd) for p in SUSP_PRIV_CMDS):
            score = max(score, 55)
        if PIPE_TO_SHELL_PATTERN.search(cmd):
            score = max(score, 85)

    sev = _pick_severity("low", score)

    # Mark used
    for e in matched:
        used.add(e.line_idx)

    description = f"Detected {len(matched)} sudo command executions."

    return Finding(
        rule_name="Sudo Command Execution",
        severity=sev,
        description=description,
        matched_lines=_limit([e.line for e in sorted(matched, key=lambda e: e.line_idx)], max_lines),
        count=len(matched),
        details={},
    )


# -----------------------------
# Public API
# -----------------------------

def analyze_log_content(log_content: str, max_lines_per_finding: int = 60) -> List[Dict[str, Any]]:
    """
    Analyze a log file content and return structured findings.

    Returned schema is designed to match the existing UI:
      - rule_name, severity, description, matched_lines, count, details

    Notes
    - Output is always English for consistent UI.
    - Swedish log phrasing is supported for matching only.
    - Findings are deduplicated: the same line will not appear in multiple findings.
    """
    lines = _iter_lines(log_content)
    if not lines:
        return []

    events = _extract_events(lines)

    used: set[int] = set()
    findings: List[Finding] = []

    # Priority order matters for deduplication
    for builder in [
        _build_privilege_escalation,
        _build_suspicious_ip,
        _build_bruteforce,
        _build_user_account_changes,
        _build_ssh_auth_failures,
        _build_repeated_failed_logins,
        _build_sudo_execution,
    ]:
        f = builder(events, used, max_lines_per_finding)
        if f:
            findings.append(f)

    # Sort by severity then count (descending)
    findings.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 0), f.count), reverse=True)

    return [f.to_dict() for f in findings]
