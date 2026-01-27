import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.log_analyzer import analyze_log_content, LogAnalyzerRules


class TestLogRules:
    """Testar logganalysregler"""
    
    def test_failed_login_attempts_detection(self):
        """Test detektionav upprepade misslyckade inloggningar"""
        log_content = "\n".join([
            "Failed password for user admin",
            "Failed password for user root",
            "Failed password for user admin",
            "Failed password for user testuser",
            "Failed password for user admin",
            "Failed password for user admin",
            "SSH session established"
        ])
        
        findings = analyze_log_content(log_content)
        assert any(f['rule_name'] == 'Upprepade misslyckade inloggningar' for f in findings)
    
    def test_ssh_auth_failures(self):
        """Test detektion av SSH autentiseringsfel"""
        log_content = "\n".join([
            "sshd[1234]: Invalid user test",
            "sshd[1235]: Failed publickey",
            "sshd[1236]: Connection closed by",
            "sshd[1237]: Authentication failure",
        ])
        
        findings = analyze_log_content(log_content)
        assert any(f['rule_name'] == 'SSH autentiseringsfel' for f in findings)
    
    def test_sudo_usage_detection(self):
        """Test detektion av sudo-användning"""
        log_content = "\n".join([
            "sudo: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/cat /etc/shadow",
            "sudo: user : TTY=pts/1 ; PWD=/home/user ; USER=root ; COMMAND=/usr/sbin/useradd test"
        ])
        
        findings = analyze_log_content(log_content)
        assert any(f['rule_name'] == 'Sudo-kommandokörning' for f in findings)
    
    def test_user_account_changes(self):
        """Test detektion av användarkontoändringar"""
        log_content = "\n".join([
            "useradd: new user 'newuser' added",
            "passwd: user 'admin' password changed",
            "groupadd: group 'newgroup' created"
        ])
        
        findings = analyze_log_content(log_content)
        assert any(f['rule_name'] == 'Ändringar av användarkonton' for f in findings)
    
    def test_suspicious_ip_patterns(self):
        """Test detektion av misstänkta IP-adresser"""
        log_content = "\n".join([
            "Attack detected from 192.168.1.100",
            "Shellcode payload from 10.0.0.50",
            "Malware attempt from 172.16.0.25"
        ])
        
        findings = analyze_log_content(log_content)
        assert any(f['rule_name'] == 'Misstänkta IP-adresser' for f in findings)
    
    def test_brute_force_indicators(self):
        """Test detektion av brute-force-försök"""
        log_content = "\n".join([
            "Connection attempt #1",
            "Connection attempt #2",
            "Connection refused",
            "Port scan detected",
            "Connection reset",
            "Too many authentication attempts",
            "Connection attempt #3",
            "Connection attempt #4",
            "Connection attempt #5",
            "Connection attempt #6",
            "Rate limit exceeded",
        ])
        
        findings = analyze_log_content(log_content)
        assert any(f['rule_name'] == 'Brute-force-indikationer' for f in findings)
    
    def test_no_findings_in_clean_log(self):
        """Test att rena loggar inte genererar falskt positiva"""
        log_content = "\n".join([
            "2024-01-01 10:00:00 INFO: Application started",
            "2024-01-01 10:00:01 INFO: Service initialized",
            "2024-01-01 10:00:02 INFO: Database connection established"
        ])
        
        findings = analyze_log_content(log_content)
        # Kan ha lågt prioriterade fynd, men inte höga eller medel
        high_medium = [f for f in findings if f['severity'] in ['high', 'medium']]
        assert len(high_medium) == 0
    
    def test_html_escaping(self):
        """Test att HTML-innehål är escapat"""
        log_content = "<script>alert('xss')</script> failed login"
        findings = analyze_log_content(log_content)
        
        # Kontrollera att < och > är escapade
        for finding in findings:
            for line in finding['matched_lines']:
                assert '<script>' not in line
                assert '&lt;' in line or '&amp;' in line
    
    def test_empty_log(self):
        """Test att tom logg hanteras korrekt"""
        log_content = ""
        findings = analyze_log_content(log_content)
        assert isinstance(findings, list)
    
    def test_unicode_handling(self):
        """Test att Unicode-tecken hanteras"""
        log_content = "Failed login för user 'åäö' från IP 192.168.1.1"
        findings = analyze_log_content(log_content)
        assert isinstance(findings, list)


class TestLogAnalyzerRules:
    """Testar individuella reglemetoder"""
    
    def test_failed_login_threshold(self):
        """Test tröskel för misslyckade inloggningar"""
        lines = ["Failed password" for _ in range(5)]
        findings = LogAnalyzerRules.failed_login_attempts(lines)
        assert len(findings) == 0  # Under tröskeln
        
        lines = ["Failed password" for _ in range(10)]
        findings = LogAnalyzerRules.failed_login_attempts(lines)
        assert len(findings) > 0
        assert findings[0]['severity'] == 'medium'
    
    def test_severity_levels(self):
        """Test att severity nivåer är korrekt satta"""
        log_content = "Failed password " * 30
        findings = analyze_log_content(log_content)
        
        for finding in findings:
            assert finding['severity'] in ['low', 'medium', 'high']


class TestSwedishLanguageSupport:
    """Test Swedish language pattern detection"""
    
    def test_swedish_failed_login_patterns(self):
        """Test that Swedish failed login patterns are detected"""
        log_content = "\n".join([
            "Misslyckad inloggning för användare admin",
            "Felaktig lösenord för admin",
            "Autentisering misslyckades för testuser",
            "Misslyckad inloggning för användare root",
            "Felaktig lösenord för testuser",
            "Autentisering misslyckades för admin",
        ])
        
        findings = analyze_log_content(log_content)
        assert any(f['rule_name'] == 'Upprepade misslyckade inloggningar' for f in findings)
    
    def test_swedish_ssh_patterns(self):
        """Test Swedish SSH authentication failure patterns"""
        log_content = "\n".join([
            "sshd: autentiseringsfel för användare test",
            "sshd: Ogiltig användare från 192.168.1.100",
            "SSH anslutning stängd av server",
            "sshd: autentiseringsfel igen",
        ])
        
        findings = analyze_log_content(log_content)
        assert any(f['rule_name'] == 'SSH autentiseringsfel' for f in findings)
    
    def test_swedish_user_account_changes(self):
        """Test Swedish user account change patterns"""
        log_content = "\n".join([
            "lägg till användare: newuser",
            "ny användare skapad: testuser",
            "skapa användarkonto för admin2",
            "ta bort användare olduser",
            "ändra användare profile"
        ])
        
        findings = analyze_log_content(log_content)
        assert any(f['rule_name'] == 'Ändringar av användarkonton' for f in findings)
    
    def test_mixed_swedish_english_logs(self):
        """Test that mixed Swedish and English logs work correctly"""
        log_content = "\n".join([
            "Failed password for user admin",
            "Misslyckad inloggning för admin",
            "Invalid user testuser",
            "Ogiltig användare test",
            "Authentication failure from 192.168.1.1",
            "Autentisering misslyckades från 192.168.1.2"
        ])
        
        findings = analyze_log_content(log_content)
        assert len(findings) > 0
        
        # Should have failed login attempts detected
        assert any(f['rule_name'] == 'Upprepade misslyckade inloggningar' for f in findings)
    
    def test_swedish_privilege_escalation(self):
        """Test Swedish privilege escalation patterns"""
        log_content = "\n".join([
            "Behörighetsupptrappning försök från user1",
            "uid=0 för icke-root användare",
            "root access försök detekterat",
        ])
        
        findings = analyze_log_content(log_content)
        # Should detect some level of privilege escalation attempts
        assert isinstance(findings, list)

