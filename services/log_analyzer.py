"""SecureOps Toolkit: Log Analyzer

This module contains the detection logic used by the Flask app and the test suite.

Key goals:
- Work with both structured syslog lines and plain, unstructured lines.
- Support both English and Swedish log phrases.
- Return a stable, test friendly structure:
    { rule_name, severity, description, matched_lines }
- Keep canonical rule_name values in Swedish for the unit tests.
- Provide UI friendly English fields (display_name) without breaking tests.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# IPv4 extractor (good enough for log analysis)
_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)


def _extract_ips(line: str) -> List[str]:
    return _IP_RE.findall(line)


def _compile(patterns: List[str], flags: int = re.IGNORECASE) -> List[re.Pattern]:
    return [re.compile(p, flags) for p in patterns]


@dataclass(frozen=True)
class Rule:
    """A detection rule.

    rule_name must remain stable because the unit tests assert on it.
    """

    rule_name: str
    display_name: str
    base_severity: str
    patterns: List[re.Pattern]
    threshold: int = 1
    severity_fn: Optional[Callable[[int], str]] = None
    description_fn: Optional[Callable[[int, Dict], str]] = None


# Patterns

FAILED_LOGIN_PATTERNS = _compile(
    [
        r"\bfailed password\b",
        r"\bauthentication failure\b",
        r"\binvalid user\b",
        r"\bfailed login\b",
        r"\bfailed publickey\b",
        # Swedish
        r"\bmisslyckad inloggning\b",
        r"\bfelaktig(?:t)? lösenord\b",
        r"\bautentisering misslyckades\b",
        r"\bogiltig användare\b",
        r"\bautentiseringsfel\b",
    ]
)

SSH_AUTH_PATTERNS = _compile(
    [
        r"\bsshd\[\d+\]:\s*invalid user\b",
        r"\bsshd\[\d+\]:\s*failed (?:password|publickey)\b",
        r"\bsshd\[\d+\]:\s*authentication failure\b",
        r"\bsshd\[\d+\]:\s*connection closed\b",
        r"\bconnection closed by\b",
        # Swedish
        r"\bsshd:\s*autentiseringsfel\b",
        r"\bsshd:\s*ogiltig användare\b",
        r"\bssh anslutning stängd\b",
        r"\banslutning stängd\b.*\bssh\b",
    ]
)

SUDO_PATTERNS = _compile(
    [
        r"^\s*sudo:",
        r"\bsudo\b.*\bcommand=",
        r"\bUSER=root\b.*\bCOMMAND=",
    ]
)

USER_ACCOUNT_PATTERNS = _compile(
    [
        r"\buseradd\b",
        r"\buserdel\b",
        r"\busermod\b",
        r"\bgroupadd\b",
        r"\bgroupdel\b",
        r"\bpasswd\b.*\bpassword changed\b",
        r"\badded to group\b",
        # Swedish
        r"\blägg till användare\b",
        r"\bny användare skapad\b",
        r"\bskapa användarkonto\b",
        r"\bta bort användare\b",
        r"\bändra användare\b",
    ]
)

SUSPICIOUS_IP_PATTERNS = _compile(
    [
        r"\battack detected\b",
        r"\bshellcode\b",
        r"\bmalware\b",
        r"\bexploit\b",
        r"\binjection\b",
        r"\bsuspicious\b.*\bfrom\b",
        r"\bfrom\b.*\bmalware\b",
    ]
)

BRUTE_FORCE_PATTERNS = _compile(
    [
        r"\bconnection attempt\b",
        r"\bport scan\b",
        r"\brate limit exceeded\b",
        r"\btoo many authentication attempts\b",
        r"\bconnection refused\b",
        r"\bconnection reset\b",
    ]
)

PRIV_ESC_PATTERNS = _compile(
    [
        r"\badded\b.*\bto group\b.*\b(sudo|wheel|admin)\b",
        r"\badd\b.*\bto group\b.*\b(sudo|wheel|admin)\b",
        r"\busermod\b.*\b-aG\b.*\b(sudo|wheel|admin)\b",
        r"\bUSER=root\b.*\bCOMMAND=",
        # Swedish
        r"\blagd till\b.*\b(sudo|wheel|admin)\b",
        r"\btilldelad\b.*\badmin\b",
    ]
)

SUSPICIOUS_EXEC_PATTERNS = _compile(
    [
        r"\b(curl|wget)\b.*\b(http|https)://",
        r"\b(curl|wget)\b.*\|\s*(?:/bin/(?:ba)?sh|sh|bash)\b",
        r"\bbase64\b.*\b-d\b.*\|\s*(?:/bin/(?:ba)?sh|sh|bash)\b",
    ]
)


# Severity functions

def _failed_login_severity(count: int) -> str:
    if count >= 20:
        return "critical"
    if count >= 10:
        return "high"
    return "medium"


def _ssh_auth_severity(count: int) -> str:
    if count >= 15:
        return "high"
    if count >= 5:
        return "medium"
    return "low"


def _user_account_severity(count: int) -> str:
    if count >= 6:
        return "high"
    return "medium"


def _suspicious_ip_severity(count: int) -> str:
    return "critical" if count >= 3 else "high"


def _brute_force_severity(count: int) -> str:
    return "critical" if count >= 12 else "high"


def _always_critical(_: int) -> str:
    return "critical"


# Canonical rules

RULES: List[Rule] = [
    Rule(
        rule_name="Upprepade misslyckade inloggningar",
        display_name="Repeated Failed Login Attempts",
        base_severity="medium",
        patterns=FAILED_LOGIN_PATTERNS,
        threshold=6,
        severity_fn=_failed_login_severity,
        description_fn=lambda c, ctx: f"Detected {c} failed login attempts.",
    ),
    Rule(
        rule_name="SSH autentiseringsfel",
        display_name="SSH Authentication Failures",
        base_severity="medium",
        patterns=SSH_AUTH_PATTERNS,
        threshold=2,
        severity_fn=_ssh_auth_severity,
        description_fn=lambda c, ctx: f"Detected {c} SSH authentication failures.",
    ),
    Rule(
        rule_name="Sudo-kommandokörning",
        display_name="Sudo Command Execution",
        base_severity="low",
        patterns=SUDO_PATTERNS,
        threshold=1,
        severity_fn=lambda c: "low",
        description_fn=lambda c, ctx: f"Detected {c} sudo command executions.",
    ),
    Rule(
        rule_name="Ändringar av användarkonton",
        display_name="User Account Changes",
        base_severity="medium",
        patterns=USER_ACCOUNT_PATTERNS,
        threshold=1,
        severity_fn=_user_account_severity,
        description_fn=lambda c, ctx: "Detected user or group account changes.",
    ),
    Rule(
        rule_name="Misstänkta IP-adresser",
        display_name="Suspicious IP Addresses",
        base_severity="high",
        patterns=SUSPICIOUS_IP_PATTERNS,
        threshold=1,
        severity_fn=_suspicious_ip_severity,
        description_fn=lambda c, ctx: (
            f"Detected suspicious activity involving IP(s): {', '.join(sorted(ctx.get('ips', [])))}."
            if ctx.get("ips")
            else "Detected suspicious IP related activity."
        ),
    ),
    Rule(
        rule_name="Brute-force-indikationer",
        display_name="Brute Force Indicators",
        base_severity="high",
        patterns=BRUTE_FORCE_PATTERNS,
        threshold=3,
        severity_fn=_brute_force_severity,
        description_fn=lambda c, ctx: "Indicators consistent with brute force or scanning activity.",
    ),
    # Extra, high value rules for a more useful analyzer
    Rule(
        rule_name="Privilege Escalation Attempts",
        display_name="Privilege Escalation Attempts",
        base_severity="critical",
        patterns=PRIV_ESC_PATTERNS,
        threshold=1,
        severity_fn=_always_critical,
        description_fn=lambda c, ctx: "Potential privilege escalation patterns detected.",
    ),
    Rule(
        rule_name="Suspicious Download or Execution",
        display_name="Suspicious Download or Execution",
        base_severity="critical",
        patterns=SUSPICIOUS_EXEC_PATTERNS,
        threshold=1,
        severity_fn=_always_critical,
        description_fn=lambda c, ctx: (
            f"Detected suspicious download or execution behavior involving: {', '.join(sorted(ctx.get('ips', [])))}."
            if ctx.get("ips")
            else "Detected suspicious download or execution behavior."
        ),
    ),
]


def analyze_log_content(log_content: str) -> List[Dict]:
    """Analyze raw log content and return a list of findings.

    Returned items always include:
    - rule_name (Swedish canonical name)
    - severity (lowercase: critical, high, medium, low)
    - description (string)
    - matched_lines (list[str])

    Extra UI fields:
    - display_name (English)
    - count (int)
    """

    if not log_content or not log_content.strip():
        return []

    raw_lines = [ln.strip("\r\n") for ln in log_content.splitlines()]
    raw_lines = [ln for ln in raw_lines if ln.strip()]

    if not raw_lines:
        return []

    matched_lines: Dict[str, List[str]] = {r.rule_name: [] for r in RULES}
    match_counts: Dict[str, int] = {r.rule_name: 0 for r in RULES}
    contexts: Dict[str, Dict] = {r.rule_name: {"ips": set()} for r in RULES}

    for line in raw_lines:
        for rule in RULES:
            if any(p.search(line) for p in rule.patterns):
                matched_lines[rule.rule_name].append(line)
                match_counts[rule.rule_name] += 1
                for ip in _extract_ips(line):
                    contexts[rule.rule_name]["ips"].add(ip)

    findings_by_rule: Dict[str, Dict] = {}

    for rule in RULES:
        count = match_counts[rule.rule_name]
        if count < rule.threshold:
            continue

        ips = sorted(contexts[rule.rule_name]["ips"])
        severity = (rule.severity_fn(count) if rule.severity_fn else rule.base_severity).lower()
        description = rule.description_fn(count, {"ips": ips}) if rule.description_fn else ""

        findings_by_rule[rule.rule_name] = {
            "rule_name": rule.rule_name,
            "display_name": rule.display_name,
            "severity": severity,
            "description": description,
            "matched_lines": matched_lines[rule.rule_name],
            "count": count,
        }

    findings = list(findings_by_rule.values())

    # Sort so Critical is always shown first, then High, Medium, Low.
    findings.sort(
        key=lambda f: (
            SEVERITY_ORDER.get(f.get("severity", ""), 99),
            (f.get("display_name") or f.get("rule_name") or "").lower(),
        )
    )

    return findings


__all__ = ["analyze_log_content"]
