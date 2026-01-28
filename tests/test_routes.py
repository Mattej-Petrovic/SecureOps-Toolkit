import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app


@pytest.fixture
def client():
    """Flask test client"""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


class TestRoutes:
    """Testar Flask routes"""
    
    def test_index_returns_200(self, client):
        """Test that / returns 200 OK"""
        response = client.get('/')
        assert response.status_code == 200
        assert b'Command Guide' in response.data
    
    def test_analyze_page_returns_200(self, client):
        """Test that /analyze GET returns 200 OK"""
        response = client.get('/analyze')
        assert response.status_code == 200
        assert b'Log Analyzer' in response.data
    
    def test_api_commands_returns_json(self, client):
        """Test att /api/commands returnerar JSON"""
        response = client.get('/api/commands')
        assert response.status_code == 200
        assert response.content_type.startswith('application/json')
        
        data = response.get_json()
        assert isinstance(data, list)
        assert len(data) > 0
        assert 'name' in data[0]
        assert 'command' in data[0]
    
    def test_analyze_post_without_file(self, client):
        """Test att POST /analyze utan fil returnerar 400"""
        response = client.post('/analyze')
        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data
    
    def test_analyze_post_empty_file(self, client):
        """Test att tom fil returnerar 400"""
        from io import BytesIO
        
        response = client.post('/analyze', data={
            'file': (BytesIO(b''), '')
        })
        assert response.status_code == 400
    
    def test_analyze_post_invalid_extension(self, client):
        """Test att felaktig filtyp returnerar 400"""
        from io import BytesIO
        
        response = client.post('/analyze', data={
            'file': (BytesIO(b'test content'), 'test.exe')
        })
        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data
    
    def test_analyze_post_with_log_file(self, client):
        """Test att .log fil processas"""
        from io import BytesIO
        
        log_content = b"Failed password for user admin\n" * 10
        
        response = client.post('/analyze', data={
            'file': (BytesIO(log_content), 'test.log')
        })
        assert response.status_code == 200
        data = response.get_json()
        assert 'findings' in data
        assert isinstance(data['findings'], list)
    
    def test_analyze_post_with_txt_file(self, client):
        """Test att .txt fil processas"""
        from io import BytesIO
        
        log_content = b"system error\n" * 5
        
        response = client.post('/analyze', data={
            'file': (BytesIO(log_content), 'system.txt')
        })
        assert response.status_code == 200
        data = response.get_json()
        assert 'findings' in data
    
    def test_analyze_findings_structure(self, client):
        """Test att findings har rätt struktur"""
        from io import BytesIO
        
        log_content = b"Failed password\n" * 20
        
        response = client.post('/analyze', data={
            'file': (BytesIO(log_content), 'test.log')
        })
        
        data = response.get_json()
        findings = data['findings']
        
        if findings:
            finding = findings[0]
            assert 'rule_name' in finding
            assert 'description' in finding
            assert 'severity' in finding
            assert 'matched_lines' in finding
            assert finding['severity'] in ['low', 'medium', 'high', 'critical']
    
    def test_file_size_limit(self, client):
        """Test at för stor fil returnerar 413"""
        from io import BytesIO
        
        # Skapa en för stor fil (> 5MB)
        large_content = b'x' * (6 * 1024 * 1024)
        
        response = client.post('/analyze', data={
            'file': (BytesIO(large_content), 'large.log')
        })
        assert response.status_code == 413
    
    def test_404_not_found(self, client):
        """Test att okänd route returnerar 404"""
        response = client.get('/nonexistent')
        assert response.status_code == 404


class TestUploadHandling:
    """Testar filuppladdningshantering"""
    
    def test_upload_with_encoding_issues(self, client):
        """Test att fil med kodningsproblem hanteras"""
        from io import BytesIO
        
        # Latin-1 encoded text
        log_content = "Misslyckad inloggning för användare\n".encode('latin-1')
        
        response = client.post('/analyze', data={
            'file': (BytesIO(log_content), 'test.log')
        })
        assert response.status_code == 200
    
    def test_upload_multiline_file(self, client):
        """Test att flurraddiga filer processas"""
        from io import BytesIO
        
        log_content = b"""
2024-01-01 10:00:00 Failed password
2024-01-01 10:00:01 Failed password
2024-01-01 10:00:02 Failed password
2024-01-01 10:00:03 Failed password
2024-01-01 10:00:04 Failed password
2024-01-01 10:00:05 Failed password
"""
        
        response = client.post('/analyze', data={
            'file': (BytesIO(log_content), 'multiline.log')
        })
        assert response.status_code == 200
        data = response.get_json()
        assert 'findings' in data
