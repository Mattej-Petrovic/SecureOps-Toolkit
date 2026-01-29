"""SecureOps Toolkit: Log Analyzer

This module contains the detection logic used by the Flask app.

Contract
The Flask UI expects analyze_log_content(log_text) -> list[dict] where each dict
contains at minimum:
  rule_name (stable Swedish name), severity (critical|high|medium|low),
  description, matched_lines.

This implementation adds optional UI fields without breaking that contract:
  id, display_name, summary, details, count, entities, time_range.

Design goals
  • Low false positives for IP extraction (validate IPv6 candidates)
  • Time aware correlation when timestamps exist
  • No duplicated findings for the same root cause
  • Short header text (summary) and richer details inside the fold
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Tuple


SEVERITY_ORDER: Dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Practical limits so the UI stays fast and the JSON stays small
_MAX_MATCHED_LINES = 200
_TOP_N = 5

# Correlation window for fail→success and burst detection
_WINDOW_SECONDS = 10 * 60


# -------------------------
# Parsing helpers
# -------------------------

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

_IPV6_CANDIDATE_RE = re.compile(r"\b[0-9A-Fa-f:]{2,}\b")


def _extract_ips(line: str) -> List[str]:
    ips: List[str] = []
    ips.extend(_IPV4_RE.findall(line))

    seen = set(ips)
    for cand in _IPV6_CANDIDATE_RE.findall(line):
        if ":" not in cand:
            continue
        try:
            ip_obj = ipaddress.ip_address(cand)
        except ValueError:
            continue
        if ip_obj.version != 6:
            continue
        ip_s = str(ip_obj)
        if ip_s not in seen:
            seen.add(ip_s)
            ips.append(ip_s)
    return ips


_KV_RE = re.compile(r"(?P<k>[A-Za-z0-9_.:]+)=(?P<v>\"[^\"]*\"|'[^']*'|\S+)")


def _parse_kv(line: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for m in _KV_RE.finditer(line):
        k = m.group("k").lower()
        v = m.group("v")
        if len(v) >= 2 and ((v[0] == v[-1] == '"') or (v[0] == v[-1] == "'")):
            v = v[1:-1]
        out[k] = v
    return out


_ISO_TS_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<rest>.*)$"
)

_SYSLOG_TS_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<rest>.*)$"
)

_APACHE_TS_RE = re.compile(r"\[(?P<ts>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\]")


def _parse_timestamp(line: str) -> Tuple[Optional[datetime], str]:
    """Return (timestamp_utc_or_none, remainder_without_ts_prefix)."""

    m = _ISO_TS_RE.match(line)
    if m:
        ts_s = m.group("ts")
        rest = m.group("rest")
        try:
            if ts_s.endswith("Z"):
                ts_s = ts_s[:-1] + "+00:00"
            if "T" not in ts_s and " " in ts_s:
                ts_s = ts_s.replace(" ", "T", 1)
            dt = datetime.fromisoformat(ts_s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc), rest
        except Exception:
            return None, line

    m = _SYSLOG_TS_RE.match(line)
    if m:
        rest = m.group("rest")
        try:
            month = datetime.strptime(m.group("mon"), "%b").month
            day = int(m.group("day"))
            hh, mm, ss = [int(x) for x in m.group("time").split(":")]
            year = datetime.now(timezone.utc).year
            dt = datetime(year, month, day, hh, mm, ss, tzinfo=timezone.utc)
            return dt, rest
        except Exception:
            return None, line

    m = _APACHE_TS_RE.search(line)
    if m:
        ts_s = m.group("ts")
        try:
            dt = datetime.strptime(ts_s, "%d/%b/%Y:%H:%M:%S %z")
            return dt.astimezone(timezone.utc), line
        except Exception:
            return None, line

    return None, line


_SSH_FAIL_USER_RE = re.compile(
    r"failed (?:password|publickey) for (?:invalid user\s+)?(?P<u>[A-Za-z0-9._-]+)",
    re.IGNORECASE,
)
_SSH_INVALID_USER_RE = re.compile(r"invalid user\s+(?P<u>[A-Za-z0-9._-]+)", re.IGNORECASE)
_SSH_ACCEPT_RE = re.compile(
    r"accepted (?:password|publickey) for\s+(?P<u>[A-Za-z0-9._-]+)", re.IGNORECASE
)
_SUDO_USER_RE = re.compile(r"\bsudo:\s*(?P<u>[A-Za-z0-9._-]+)\s*:", re.IGNORECASE)


def _extract_user(line: str, kv: Dict[str, str]) -> Optional[str]:
    for k in ("user", "username", "acct", "account", "src_user", "dst_user"):
        v = kv.get(k)
        if v:
            return v

    m = _SSH_ACCEPT_RE.search(line)
    if m:
        return m.group("u")
    m = _SSH_FAIL_USER_RE.search(line)
    if m:
        return m.group("u")
    m = _SSH_INVALID_USER_RE.search(line)
    if m:
        return m.group("u")
    m = _SUDO_USER_RE.search(line)
    if m:
        return m.group("u")
    return None


def _sha_id(*parts: str) -> str:
    h = hashlib.sha1()
    for p in parts:
        h.update(p.encode("utf-8", errors="ignore"))
        h.update(b"\0")
    return h.hexdigest()[:16]


# -------------------------
# Normalization
# -------------------------


@dataclass(frozen=True)
class Event:
    ts: Optional[datetime]
    raw: str
    msg: str
    ips: Tuple[str, ...]
    user: Optional[str]
    kind: str


_AUTH_FAIL_RE = re.compile(
    r"\b(failed password|authentication failure|invalid user|failed publickey|logon failure|eventid\s*=\s*4625|misslyckad inloggning|autentisering misslyckades|ogiltig användare)\b",
    re.IGNORECASE,
)
_AUTH_OK_RE = re.compile(
    r"\b(accepted password|accepted publickey|eventid\s*=\s*4624)\b",
    re.IGNORECASE,
)

_SUDO_FAIL_RE = re.compile(r"incorrect password attempts", re.IGNORECASE)
_SUDO_RE = re.compile(r"^\s*sudo:", re.IGNORECASE)

_ACCOUNT_CHANGE_RE = re.compile(
    r"\b(useradd|userdel|usermod|groupadd|groupdel|password changed|passwd\[|new user:)\b",
    re.IGNORECASE,
)

_PRIV_ESC_RE = re.compile(
    r"\b(add(?:ed)?\s+to\s+group\s+(sudo|wheel|admin)|add(?:ed)?\s+['\"]?.+['\"]?\s+to\s+group\s+['\"]?(sudo|wheel|admin)['\"]?|usermod\b.*\b-aG\b.*\b(sudo|wheel|admin)\b|sudoers)\b",
    re.IGNORECASE,
)

_WEB_SQLI_RE = re.compile(r"\b(union\s+all\s+select|union\s+select|or\s+1=1|%27\s*or\s*1%3d1|information_schema|sleep\()\b", re.IGNORECASE)
_WEB_XSS_RE = re.compile(r"<script|%3cscript|onerror=|javascript:", re.IGNORECASE)
_WEB_LFI_RE = re.compile(r"\b(\.\./|%2e%2e%2f|etc%2fpasswd|/etc/passwd)\b", re.IGNORECASE)

_SUSP_EXEC_RE = re.compile(r"\b(curl|wget)\b.*\bhttps?://|\bbase64\b.*\b-d\b.*\|\s*(sh|bash)\b", re.IGNORECASE)


def _classify(kind_line: str) -> str:
    """Deterministic priority mapping."""
    if _PRIV_ESC_RE.search(kind_line):
        return "privilege_change"
    if _SUSP_EXEC_RE.search(kind_line):
        return "suspicious_exec"
    if _ACCOUNT_CHANGE_RE.search(kind_line):
        return "account_change"
    if _AUTH_OK_RE.search(kind_line):
        return "auth_success"
    if _AUTH_FAIL_RE.search(kind_line):
        return "auth_fail"
    if _SUDO_RE.search(kind_line):
        return "sudo_fail" if _SUDO_FAIL_RE.search(kind_line) else "sudo_exec"
    if _WEB_SQLI_RE.search(kind_line):
        return "web_sqli"
    if _WEB_XSS_RE.search(kind_line):
        return "web_xss"
    if _WEB_LFI_RE.search(kind_line):
        return "web_lfi"
    return "other"


def _events_from_lines(lines: Iterable[str]) -> List[Event]:
    out: List[Event] = []
    for raw in lines:
        line = raw.strip("\r\n")
        if not line.strip():
            continue
        ts, msg = _parse_timestamp(line)
        kv = _parse_kv(line)
        ips = tuple(_extract_ips(line))
        user = _extract_user(line, kv)
        kind = _classify(line)
        out.append(Event(ts=ts, raw=line, msg=msg, ips=ips, user=user, kind=kind))
    return out


# -------------------------
# Findings builder
# -------------------------


def _fmt_top(counter: Counter, n: int = _TOP_N) -> str:
    items = counter.most_common(n)
    return ", ".join(f"{k} ({v})" for k, v in items)


def _time_range(ts_list: List[datetime]) -> Optional[str]:
    if not ts_list:
        return None
    start = min(ts_list)
    end = max(ts_list)
    return f"{start.isoformat().replace('+00:00','Z')} to {end.isoformat().replace('+00:00','Z')}"


def _cap_lines(lines: List[str]) -> Tuple[List[str], Optional[str]]:
    if len(lines) <= _MAX_MATCHED_LINES:
        return lines, None
    kept = lines[:_MAX_MATCHED_LINES]
    return kept, f"Matched lines truncated: showing {_MAX_MATCHED_LINES} of {len(lines)}."


def analyze_log_content(log_content: str) -> List[Dict]:
    """Analyze raw log content and return a list of findings."""

    if not log_content or not log_content.strip():
        return []

    raw_lines = [ln for ln in log_content.replace("\r\n", "\n").replace("\r", "\n").split("\n") if ln.strip()]
    if not raw_lines:
        return []

    events = _events_from_lines(raw_lines)

    # Collect per IP and per user
    auth_fail_by_ip: Dict[str, List[Event]] = defaultdict(list)
    auth_ok_by_ip: Dict[str, List[Event]] = defaultdict(list)
    auth_fail_user_by_ip: Dict[str, Counter] = defaultdict(Counter)

    sudo_events: List[Event] = []
    account_events: List[Event] = []
    priv_events: List[Event] = []
    web_events_by_ip: Dict[str, List[Event]] = defaultdict(list)
    exec_events: List[Event] = []

    for ev in events:
        if ev.kind == "auth_fail":
            for ip in ev.ips or ("(no-ip)",):
                auth_fail_by_ip[ip].append(ev)
                if ev.user:
                    auth_fail_user_by_ip[ip][ev.user] += 1
        elif ev.kind == "auth_success":
            for ip in ev.ips or ("(no-ip)",):
                auth_ok_by_ip[ip].append(ev)
        elif ev.kind in ("sudo_exec", "sudo_fail"):
            sudo_events.append(ev)
        elif ev.kind == "account_change":
            account_events.append(ev)
        elif ev.kind == "privilege_change":
            priv_events.append(ev)
        elif ev.kind in ("web_sqli", "web_xss", "web_lfi"):
            for ip in ev.ips or ("(no-ip)",):
                web_events_by_ip[ip].append(ev)
        elif ev.kind == "suspicious_exec":
            exec_events.append(ev)

    findings: List[Dict] = []

    # 1) Repeated failed logins, per IP (pick only those above threshold)
    for ip, fails in auth_fail_by_ip.items():
        if ip == "(no-ip)":
            continue
        if len(fails) < 6:
            continue

        ts_list = [e.ts for e in fails if e.ts]
        tr = _time_range([t for t in ts_list if t])

        top_users = auth_fail_user_by_ip[ip]
        user_summary = _fmt_top(top_users)

        # Correlation: any success from same IP within window after last fail
        fail_then_success = False
        if ts_list and auth_ok_by_ip.get(ip):
            last_fail = max(t for t in ts_list if t)
            for ok in auth_ok_by_ip[ip]:
                if ok.ts and 0 <= (ok.ts - last_fail).total_seconds() <= _WINDOW_SECONDS:
                    fail_then_success = True
                    break

        severity = "high"
        if len(fails) >= 20:
            severity = "critical"
        elif fail_then_success:
            severity = "critical"
        elif len(fails) >= 10:
            severity = "high"
        else:
            severity = "high"

        summary = f"{len(fails)} misslyckade inloggningar från {ip}."

        details_lines: List[str] = []
        if user_summary:
            details_lines.append(f"Top användarnamn: {user_summary}.")
        if fail_then_success:
            details_lines.append("Mönster: misslyckanden följt av lyckad inloggning.")
        if tr:
            details_lines.append(f"Time window: {tr}.")

        matched = [e.raw for e in fails]
        matched, trunc_note = _cap_lines(matched)
        if trunc_note:
            details_lines.append(trunc_note)

        details = "\n".join(details_lines) if details_lines else ""

        findings.append(
            {
                "id": _sha_id("auth_fail", ip, str(len(fails)), tr or ""),
                "rule_name": "Upprepade misslyckade inloggningar",
                "display_name": "Repeated Failed Login Attempts",
                "severity": severity,
                "summary": summary,
                "description": f"Detected {len(fails)} failed login attempts.",
                "details": details,
                "matched_lines": matched,
                "count": len(fails),
                "entities": {"ip": ip, "users": [u for u, _ in top_users.most_common(_TOP_N)]},
                "time_range": tr,
            }
        )

    # 2) SSH auth failures (low volume), only if no repeated finding exists
    if not any(f["rule_name"] == "Upprepade misslyckade inloggningar" for f in findings):
        # Aggregate all auth_fail events that look like sshd
        ssh_fails = [e for e in events if e.kind == "auth_fail" and "sshd" in e.raw.lower()]
        if len(ssh_fails) >= 2:
            ips = Counter(ip for e in ssh_fails for ip in e.ips)
            users = Counter(e.user for e in ssh_fails if e.user)
            ts_list = [e.ts for e in ssh_fails if e.ts]
            tr = _time_range([t for t in ts_list if t])
            sev = "medium" if len(ssh_fails) < 10 else "high"
            summary = f"{len(ssh_fails)} SSH autentiseringsfel." 
            details_lines = []
            if ips:
                details_lines.append(f"Top IP: {_fmt_top(ips)}.")
            if users:
                details_lines.append(f"Top användare: {_fmt_top(users)}.")
            if tr:
                details_lines.append(f"Time window: {tr}.")
            matched, trunc_note = _cap_lines([e.raw for e in ssh_fails])
            if trunc_note:
                details_lines.append(trunc_note)
            findings.append(
                {
                    "id": _sha_id("ssh_auth", str(len(ssh_fails)), tr or ""),
                    "rule_name": "SSH autentiseringsfel",
                    "display_name": "SSH Authentication Failures",
                    "severity": sev,
                    "summary": summary,
                    "description": f"Detected {len(ssh_fails)} SSH authentication failures.",
                    "details": "\n".join(details_lines),
                    "matched_lines": matched,
                    "count": len(ssh_fails),
                    "entities": {"ips": [k for k, _ in ips.most_common(_TOP_N)], "users": [k for k, _ in users.most_common(_TOP_N)]},
                    "time_range": tr,
                }
            )

    # 3) Sudo command execution, separate note for incorrect passwords
    if sudo_events:
        bad_pw = [e for e in sudo_events if e.kind == "sudo_fail"]
        all_sudo = [e for e in sudo_events if e.kind in ("sudo_exec", "sudo_fail")]
        users = Counter(e.user for e in all_sudo if e.user)
        ts_list = [e.ts for e in all_sudo if e.ts]
        tr = _time_range([t for t in ts_list if t])
        sev = "low"
        details_lines = []
        if bad_pw:
            sev = "medium" if len(bad_pw) >= 3 else "low"
            details_lines.append(f"Felaktiga sudo lösenord: {len(bad_pw)}.")
        if users:
            details_lines.append(f"Users: {_fmt_top(users)}.")
        if tr:
            details_lines.append(f"Time window: {tr}.")
        matched, trunc_note = _cap_lines([e.raw for e in all_sudo])
        if trunc_note:
            details_lines.append(trunc_note)
        findings.append(
            {
                "id": _sha_id("sudo", str(len(all_sudo)), tr or ""),
                "rule_name": "Sudo-kommandokörning",
                "display_name": "Sudo Command Execution",
                "severity": sev,
                "summary": f"{len(all_sudo)} sudo händelser.",
                "description": f"Detected {len(all_sudo)} sudo command executions.",
                "details": "\n".join(details_lines),
                "matched_lines": matched,
                "count": len(all_sudo),
                "entities": {"users": [k for k, _ in users.most_common(_TOP_N)]},
                "time_range": tr,
            }
        )

    # 4) Account changes
    if account_events:
        users = Counter(e.user for e in account_events if e.user)
        ips = Counter(ip for e in account_events for ip in e.ips)
        ts_list = [e.ts for e in account_events if e.ts]
        tr = _time_range([t for t in ts_list if t])
        sev = "medium"
        details_lines = []
        if users:
            details_lines.append(f"Users: {_fmt_top(users)}.")
        if ips:
            details_lines.append(f"IPs: {_fmt_top(ips)}.")
        if tr:
            details_lines.append(f"Time window: {tr}.")
        matched, trunc_note = _cap_lines([e.raw for e in account_events])
        if trunc_note:
            details_lines.append(trunc_note)
        findings.append(
            {
                "id": _sha_id("acct", str(len(account_events)), tr or ""),
                "rule_name": "Ändringar av användarkonton",
                "display_name": "User Account Changes",
                "severity": sev,
                "summary": f"{len(account_events)} kontoändringar.",
                "description": "Detected user or group account changes.",
                "details": "\n".join(details_lines),
                "matched_lines": matched,
                "count": len(account_events),
                "entities": {"users": [k for k, _ in users.most_common(_TOP_N)], "ips": [k for k, _ in ips.most_common(_TOP_N)]},
                "time_range": tr,
            }
        )

    # 5) Privilege escalation attempts
    if priv_events:
        ips = Counter(ip for e in priv_events for ip in e.ips)
        users = Counter(e.user for e in priv_events if e.user)
        ts_list = [e.ts for e in priv_events if e.ts]
        tr = _time_range([t for t in ts_list if t])
        details_lines = []
        if users:
            details_lines.append(f"Users: {_fmt_top(users)}.")
        if ips:
            details_lines.append(f"IPs: {_fmt_top(ips)}.")
        if tr:
            details_lines.append(f"Time window: {tr}.")
        matched, trunc_note = _cap_lines([e.raw for e in priv_events])
        if trunc_note:
            details_lines.append(trunc_note)
        findings.append(
            {
                "id": _sha_id("priv", str(len(priv_events)), tr or ""),
                "rule_name": "Privilege Escalation Attempts",
                "display_name": "Privilege Escalation Attempts",
                "severity": "critical",
                "summary": f"{len(priv_events)} möjliga privilege escalation händelser.",
                "description": "Potential privilege escalation patterns detected.",
                "details": "\n".join(details_lines),
                "matched_lines": matched,
                "count": len(priv_events),
                "entities": {"users": [k for k, _ in users.most_common(_TOP_N)], "ips": [k for k, _ in ips.most_common(_TOP_N)]},
                "time_range": tr,
            }
        )

    # 6) Web attack patterns per IP
    for ip, wevs in web_events_by_ip.items():
        if ip == "(no-ip)":
            continue
        kinds = Counter(e.kind for e in wevs)
        sev = "high"
        if kinds.get("web_sqli", 0) >= 1 and kinds.get("web_lfi", 0) >= 1:
            sev = "critical"
        if kinds.get("web_sqli", 0) >= 2:
            sev = "critical"
        summary_parts = []
        if kinds.get("web_sqli"):
            summary_parts.append(f"SQLi: {kinds['web_sqli']}")
        if kinds.get("web_xss"):
            summary_parts.append(f"XSS: {kinds['web_xss']}")
        if kinds.get("web_lfi"):
            summary_parts.append(f"LFI: {kinds['web_lfi']}")
        summary = f"Webbattacker från {ip}. " + ", ".join(summary_parts) + "."
        ts_list = [e.ts for e in wevs if e.ts]
        tr = _time_range([t for t in ts_list if t])
        details_lines = [f"Typer: {', '.join(f'{k} ({v})' for k, v in kinds.items())}."]
        if tr:
            details_lines.append(f"Time window: {tr}.")
        matched, trunc_note = _cap_lines([e.raw for e in wevs])
        if trunc_note:
            details_lines.append(trunc_note)
        findings.append(
            {
                "id": _sha_id("web", ip, tr or ""),
                "rule_name": "Misstänkta webbförfrågningar",
                "display_name": "Suspicious Web Requests",
                "severity": sev,
                "summary": summary,
                "description": "Detected suspicious web request patterns.",
                "details": "\n".join(details_lines),
                "matched_lines": matched,
                "count": len(wevs),
                "entities": {"ip": ip},
                "time_range": tr,
            }
        )

    # 7) Suspicious download or execution
    if exec_events:
        ips = Counter(ip for e in exec_events for ip in e.ips)
        ts_list = [e.ts for e in exec_events if e.ts]
        tr = _time_range([t for t in ts_list if t])
        details_lines = []
        if ips:
            details_lines.append(f"IPs: {_fmt_top(ips)}.")
        if tr:
            details_lines.append(f"Time window: {tr}.")
        matched, trunc_note = _cap_lines([e.raw for e in exec_events])
        if trunc_note:
            details_lines.append(trunc_note)
        findings.append(
            {
                "id": _sha_id("exec", str(len(exec_events)), tr or ""),
                "rule_name": "Suspicious Download or Execution",
                "display_name": "Suspicious Download or Execution",
                "severity": "critical",
                "summary": f"{len(exec_events)} misstänkta nedladdnings eller körmönster.",
                "description": "Detected suspicious download or execution behavior.",
                "details": "\n".join(details_lines),
                "matched_lines": matched,
                "count": len(exec_events),
                "entities": {"ips": [k for k, _ in ips.most_common(_TOP_N)]},
                "time_range": tr,
            }
        )

    # De duplicate: if both privilege and account changes exist, keep both
    # but avoid multiple web findings for same IP by id.

    findings.sort(
        key=lambda f: (
            SEVERITY_ORDER.get(str(f.get("severity", "")).lower(), 99),
            (f.get("display_name") or f.get("rule_name") or "").lower(),
        )
    )

    return findings


__all__ = ["analyze_log_content"]
