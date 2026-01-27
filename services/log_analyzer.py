import re
from collections import defaultdict
from html import escape

class LogAnalyzerRules:
    """Log analysis rules"""
    
    @staticmethod
    def failed_login_attempts(lines):
        """Detects repeated failed login attempts"""
        findings = []
        failed_logins = defaultdict(int)
        matched_lines = []
        
        # English and Swedish patterns
        patterns = [
            r'(?:Failed|FAILED|failed|Failed password|FAILED PASSWORD|Invalid user|invalid user)',
            r'Authentication failure',
            r'Failed publickey',
            r'Disconnected by authenticating user',
            # Swedish patterns
            r'(?:Misslyckad|misslyckad|Felaktig)',
            r'(?:Autentisering misslyckades|autentisering misslyckades)',
            r'(?:Ogiltig användare|ogiltig användare)'
        ]
        
        for line in lines:
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    failed_logins['count'] += 1
                    if len(matched_lines) < 5:
                        matched_lines.append(line.strip()[:200])
                    break
        
        if failed_logins['count'] > 5:
            severity = 'high' if failed_logins['count'] > 20 else 'medium'
            findings.append({
                'rule_name': 'Repeated Failed Login Attempts',
                'description': f"Detected {failed_logins['count']} failed login attempts",
                'severity': severity,
                'matched_lines': matched_lines
            })
        
        return findings
    
    @staticmethod
    def ssh_auth_failures(lines):
        """Detects SSH authentication failures"""
        findings = []
        ssh_failures = []
        
        # English and Swedish patterns
        patterns = [
            r'sshd.*authentication failure',
            r'sshd.*Invalid user',
            r'sshd.*Failed publickey',
            r'sshd.*Connection closed by',
            r'ssh.*Received disconnect',
            # Swedish patterns
            r'sshd.*autentiseringsfel',
            r'sshd.*Ogiltig användare',
            r'SSH.*anslutning stängd'
        ]
        
        for line in lines:
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    ssh_failures.append(line.strip()[:200])
                    break
        
        if len(ssh_failures) > 3:
            findings.append({
                'rule_name': 'SSH Authentication Failures',
                'description': f"Detected {len(ssh_failures)} SSH authentication failures",
                'severity': 'medium',
                'matched_lines': ssh_failures[:5]
            })
        
        return findings
    
    @staticmethod
    def sudo_usage(lines):
        """Detects sudo command usage"""
        findings = []
        sudo_lines = []
        
        # English and Swedish patterns
        for line in lines:
            if (re.search(r'\bsudo\b', line, re.IGNORECASE) and 'sudo:' in line) or \
               (re.search(r'\bsudo\b', line, re.IGNORECASE) and re.search(r'körning|kördning|command', line, re.IGNORECASE)):
                sudo_lines.append(line.strip()[:200])
        
        if len(sudo_lines) > 0:
            findings.append({
                'rule_name': 'Sudo Command Execution',
                'description': f"Detected {len(sudo_lines)} sudo executions",
                'severity': 'low',
                'matched_lines': sudo_lines[:5]
            })
        
        return findings
    
    @staticmethod
    def user_account_changes(lines):
        """Detects user account modifications"""
        findings = []
        account_changes = []
        
        # English and Swedish patterns
        patterns = [
            r'useradd\b',
            r'userdel\b',
            r'usermod\b',
            r'passwd\b',
            r'groupadd\b',
            r'new user',
            # Swedish patterns
            r'lägg till användare|ny användare|skapa användar',
            r'ta bort användar|radera användar',
            r'ändra användar|modify user',
            r'ny grupp|ny lösenord'
        ]
        
        for line in lines:
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    account_changes.append(line.strip()[:200])
                    break
        
        if len(account_changes) > 0:
            findings.append({
                'rule_name': 'User Account Changes',
                'description': f"Detected {len(account_changes)} user account modifications",
                'severity': 'medium',
                'matched_lines': account_changes[:5]
            })
        
        return findings
    
    @staticmethod
    def suspicious_ip_patterns(lines):
        """Detects suspicious IP address patterns"""
        findings = []
        suspicious_ips = defaultdict(int)
        matched_lines = []
        
        # IP pattern
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        
        # Suspicious patterns
        keywords = ['attack', 'breach', 'exploit', 'payload', 'shellcode', 'injection', 'malware']
        
        for line in lines:
            for keyword in keywords:
                if re.search(keyword, line, re.IGNORECASE):
                    ips = re.findall(ip_pattern, line)
                    for ip in ips:
                        suspicious_ips[ip] += 1
                        if len(matched_lines) < 5:
                            matched_lines.append(line.strip()[:200])
                    break
        
        if suspicious_ips:
            findings.append({
                'rule_name': 'Suspicious IP Addresses',
                'description': f"Detected {len(suspicious_ips)} IP addresses with suspicious activity",
                'severity': 'high',
                'matched_lines': matched_lines
            })
        
        return findings
    
    @staticmethod
    def brute_force_indicators(lines):
        """Detects potential brute-force attempts"""
        findings = []
        connection_attempts = defaultdict(int)
        matched_lines = []
        
        patterns = [
            r'Connection attempt',
            r'Connection refused',
            r'Connection reset',
            r'Port scan',
            r'Too many authentication',
            r'Rate limit'
        ]
        
        for line in lines:
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    connection_attempts['count'] += 1
                    if len(matched_lines) < 5:
                        matched_lines.append(line.strip()[:200])
                    break
        
        if connection_attempts['count'] > 10:
            severity = 'high' if connection_attempts['count'] > 30 else 'medium'
            findings.append({
                'rule_name': 'Brute-Force Indicators',
                'description': f"Detected {connection_attempts['count']} connection attempts",
                'severity': severity,
                'matched_lines': matched_lines
            })
        
        return findings
    
    @staticmethod
    def privilege_escalation(lines):
        """Detects potential privilege escalation"""
        findings = []
        escalation_attempts = []
        
        patterns = [
            r'privilege|privileged|elevated',
            r'root access',
            r'uid=0',
            r'SETUID',
            r'CAP_SYS'
        ]
        
        for line in lines:
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    escalation_attempts.append(line.strip()[:200])
                    break
        
        if len(escalation_attempts) > 2:
            findings.append({
                'rule_name': 'Privilege Escalation Attempts',
                'description': f"Detected {len(escalation_attempts)} potential privilege escalation attempts",
                'severity': 'high',
                'matched_lines': escalation_attempts[:5]
            })
        
        return findings
    
    @staticmethod
    def file_access_anomalies(lines):
        """Detects file access anomalies"""
        findings = []
        access_anomalies = []
        
        patterns = [
            r'Permission denied',
            r'Access denied',
            r'Unauthorized access',
            r'Cannot access',
            r'Operation not permitted',
            r'read-only file system'
        ]
        
        for line in lines:
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    access_anomalies.append(line.strip()[:200])
                    break
        
        if len(access_anomalies) > 3:
            findings.append({
                'rule_name': 'File Access Anomalies',
                'description': f"Detected {len(access_anomalies)} file access anomalies",
                'severity': 'low',
                'matched_lines': access_anomalies[:5]
            })
        
        return findings


def analyze_log_content(content):
    """Main analysis method that runs all rules"""
    # Split into lines
    lines = content.split('\n')
    lines = [line for line in lines if line.strip()]
    
    all_findings = []
    
    # Run all rules
    rule_methods = [
        LogAnalyzerRules.failed_login_attempts,
        LogAnalyzerRules.ssh_auth_failures,
        LogAnalyzerRules.sudo_usage,
        LogAnalyzerRules.user_account_changes,
        LogAnalyzerRules.suspicious_ip_patterns,
        LogAnalyzerRules.brute_force_indicators,
        LogAnalyzerRules.privilege_escalation,
        LogAnalyzerRules.file_access_anomalies
    ]
    
    for rule_method in rule_methods:
        try:
            findings = rule_method(lines)
            all_findings.extend(findings)
        except Exception as e:
            # Ignore errors from individual rules
            pass
    
    # Sort by severity (high → medium → low)
    severity_order = {'high': 0, 'medium': 1, 'low': 2}
    all_findings.sort(key=lambda x: severity_order.get(x.get('severity', 'low'), 999))
    
    # HTML-escape all text strings
    for finding in all_findings:
        finding['rule_name'] = escape(finding['rule_name'])
        finding['description'] = escape(finding['description'])
        finding['matched_lines'] = [escape(line) for line in finding['matched_lines']]
    
    return all_findings
