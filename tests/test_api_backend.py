"""Integration tests for FastAPI backend."""

import pytest
from fastapi.testclient import TestClient
from src.baitblocker.backend_api import app


@pytest.fixture
def client():
    """Create a test client for the FastAPI app."""
    return TestClient(app)


class TestHealthEndpoints:
    """Test suite for health check endpoints."""

    def test_root_redirect(self, client):
        """Test that root redirects to docs."""
        response = client.get("/", follow_redirects=True)
        assert response.status_code == 200

    def test_test_keys_endpoint(self, client):
        """Test the /test-keys endpoint."""
        response = client.get("/test-keys")
        assert response.status_code == 200
        
        data = response.json()
        assert "google_loaded" in data
        assert "vt_loaded" in data
        assert isinstance(data["google_loaded"], bool)
        assert isinstance(data["vt_loaded"], bool)


class TestAnalyzeEndpoint:
    """Test suite for the /analyze endpoint."""

    def test_analyze_with_url_only(self, client):
        """Test analyzing a URL without email text."""
        payload = {
            "url": "https://example.com",
            "email_text": None,
            "run_sandbox": False
        }
        response = client.post("/analyze", json=payload)
        
        assert response.status_code == 200
        data = response.json()
        
        assert "local_report" in data
        assert "external_report" in data
        assert "sandbox" in data
        assert data["local_report"]["url_lexical_analysis"] is not None

    def test_analyze_with_email_only(self, client):
        """Test analyzing email text without URL."""
        payload = {
            "url": None,
            "email_text": "Urgent: Update your password immediately!",
            "run_sandbox": False
        }
        response = client.post("/analyze", json=payload)
        
        assert response.status_code == 200
        assert response.headers.get("x-cache") == "BYPASS"
        data = response.json()
        
        assert data["local_report"]["url_lexical_analysis"] is None
        # Email analysis depends on API key availability
        if data["local_report"]["email_text_analysis"]:
            assert "phishing_probability" in data["local_report"]["email_text_analysis"]

    def test_analyze_cache_header_for_url_requests(self, client):
        """Test URL analyses expose an explicit cache status header."""
        payload = {
            "url": "https://cache-status-check.example",
            "email_text": None,
            "run_sandbox": False,
        }

        first = client.post("/analyze", json=payload)
        assert first.status_code == 200
        assert first.headers.get("x-cache") in {"MISS", "HIT"}

        second = client.post("/analyze", json=payload)
        assert second.status_code == 200
        assert second.headers.get("x-cache") in {"MISS", "HIT"}

    def test_analyze_no_input(self, client):
        """Test that analyze rejects requests with no URL or email."""
        payload = {
            "url": None,
            "email_text": None,
            "run_sandbox": False
        }
        response = client.post("/analyze", json=payload)
        
        assert response.status_code == 400
        assert "Must provide" in response.json()["detail"]

    def test_analyze_response_structure(self, client):
        """Test that response has correct structure."""
        payload = {
            "url": "https://google.com",
            "email_text": None,
            "run_sandbox": False
        }
        response = client.post("/analyze", json=payload)
        
        assert response.status_code == 200
        data = response.json()
        
        # Check top-level structure
        assert "local_report" in data
        assert "external_report" in data
        assert "sandbox" in data
        
        # Check local_report structure
        local = data["local_report"]
        assert "url_lexical_analysis" in local
        assert "email_text_analysis" in local
        
        # Check external_report structure
        external = data["external_report"]
        assert "status" in external
        assert "input_received" in external
        assert "google_safe_browsing" in external
        assert "risk_level_from_virus_total" in external
        assert "engines_flagged_on_vt" in external
        
        # Check sandbox structure
        sandbox = data["sandbox"]
        assert "sandbox_status" in sandbox
        assert "final_destination" in sandbox
        assert "screenshot_data" in sandbox

    def test_analyze_url_lexical_analysis(self, client):
        """Test URL lexical analysis in response."""
        payload = {
            "url": "https://example.com",
            "email_text": None,
            "run_sandbox": False
        }
        response = client.post("/analyze", json=payload)
        
        data = response.json()
        lex_analysis = data["local_report"]["url_lexical_analysis"]
        
        assert "url" in lex_analysis
        assert "verdict" in lex_analysis
        assert "risk_score" in lex_analysis
        assert "reasons" in lex_analysis
        
        assert isinstance(lex_analysis["risk_score"], (int, float))
        assert 0.0 <= lex_analysis["risk_score"] <= 1.0
        assert lex_analysis["verdict"] in ["Safe", "Suspicious", "High Risk", "ERROR"]
        assert isinstance(lex_analysis["reasons"], list)

    def test_analyze_suspicious_url(self, client):
        """Test analyzing a suspicious URL."""
        payload = {
            "url": "https://suspicious-login.xyz",
            "email_text": None,
            "run_sandbox": False
        }
        response = client.post("/analyze", json=payload)
        
        assert response.status_code == 200
        data = response.json()
        
        lex = data["local_report"]["url_lexical_analysis"]
        # Should flag as suspicious or high risk due to keywords and TLD
        assert lex["risk_score"] > 0.0

    def test_analyze_skip_sandbox(self, client):
        """Test that sandbox is skipped when run_sandbox=False."""
        payload = {
            "url": "https://example.com",
            "email_text": None,
            "run_sandbox": False
        }
        response = client.post("/analyze", json=payload)
        
        data = response.json()
        sandbox = data["sandbox"]
        
        assert "Skipped" in sandbox["sandbox_status"] or sandbox["sandbox_status"] == "N/A"
        assert sandbox["screenshot_data"] is None

    def test_analyze_cache_hit_restores_ml_report(self, client):
        """Test that repeated analyze requests preserve ml_report via cache rehydration."""
        payload = {
            "url": "https://cache-restore-check.example",
            "email_text": None,
            "run_sandbox": False
        }

        first = client.post("/analyze", json=payload)
        assert first.status_code == 200
        first_data = first.json()
        assert first_data["local_report"]["ml_report"] is not None

        second = client.post("/analyze", json=payload)
        assert second.status_code == 200
        second_data = second.json()
        assert second_data["local_report"]["ml_report"] is not None


class TestSecurityScanEndpoint:
    """Test suite for the /v1/security/scan endpoint."""

    def test_security_scan_valid_url(self, client):
        """Test security scan endpoint with valid URL."""
        response = client.get("/v1/security/scan?url=https://google.com")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "verdict" in data
        assert "risk_score" in data
        assert "reasons" in data

    def test_security_scan_missing_url(self, client):
        """Test security scan endpoint without URL."""
        response = client.get("/v1/security/scan")
        
        assert response.status_code == 422  # Unprocessable Entity

    def test_security_scan_cache_header(self, client):
        """Test that security scan sets cache header."""
        response = client.get("/v1/security/scan?url=https://example.com")
        
        assert response.status_code == 200
        # Check cache header is set
        assert "x-cache" in response.headers or "X-Cache" in response.headers


class TestResponseValidation:
    """Test suite for response validation."""

    def test_analyze_response_types(self, client):
        """Test that response data types are correct."""
        payload = {
            "url": "https://test.com",
            "email_text": None,
            "run_sandbox": False
        }
        response = client.post("/analyze", json=payload)
        data = response.json()
        
        # Check types
        assert isinstance(data["local_report"], dict)
        assert isinstance(data["external_report"], dict)
        assert isinstance(data["sandbox"], dict)
        
        lex = data["local_report"]["url_lexical_analysis"]
        if lex:
            assert isinstance(lex["url"], str)
            assert isinstance(lex["verdict"], str)
            assert isinstance(lex["risk_score"], (int, float))
            assert isinstance(lex["reasons"], list)

    def test_external_report_types(self, client):
        """Test external report response types."""
        payload = {
            "url": "https://test.com",
            "email_text": None,
            "run_sandbox": False
        }
        response = client.post("/analyze", json=payload)
        data = response.json()
        
        ext = data["external_report"]
        assert isinstance(ext["status"], str)
        assert isinstance(ext["input_received"], str)
        # Other fields can be None or string
        if ext["google_safe_browsing"]:
            assert isinstance(ext["google_safe_browsing"], str)
        if ext["risk_level_from_virus_total"]:
            assert isinstance(ext["risk_level_from_virus_total"], str)

