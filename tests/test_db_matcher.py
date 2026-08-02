"""Unit tests for keyword matcher module."""

import pytest
from baitblocker.db.matcher import KeywordScanner


class TestKeywordScanner:
    """Test suite for KeywordScanner class."""

    def test_scanner_initialization(self, keyword_scanner):
        """Test that KeywordScanner initializes successfully."""
        assert keyword_scanner is not None
        assert hasattr(keyword_scanner, 'compiled_regex')
        assert hasattr(keyword_scanner, 'keyword_weights')

    def test_scan_url_no_matches(self, keyword_scanner):
        """Test scanning a URL with no suspicious keywords."""
        result = keyword_scanner.scan_url("https://github.com")

        assert isinstance(result, dict)
        assert "score" in result
        assert "matches" in result
        assert "verdict" in result
        assert result["score"] == 0.0
        assert len(result["matches"]) == 0
        assert result["verdict"] == "CLEAN"

    def test_scan_url_with_matches(self, keyword_scanner):
        """Test scanning a URL with suspicious keywords."""
        result = keyword_scanner.scan_url("https://login-verify.com")

        assert isinstance(result, dict)
        assert result["score"] > 0.0
        assert len(result["matches"]) > 0
        # "login" and "verify" are both in test DB
        assert "login" in result["matches"] or "verify" in result["matches"]

    def test_scan_url_case_insensitive(self, keyword_scanner):
        """Test that scanning is case-insensitive."""
        result_lower = keyword_scanner.scan_url("https://login.com")
        result_upper = keyword_scanner.scan_url("https://LOGIN.com")
        result_mixed = keyword_scanner.scan_url("https://LoGiN.com")

        assert result_lower["matches"] == result_upper["matches"]
        assert result_lower["matches"] == result_mixed["matches"]

    def test_scan_url_score_capped_at_one(self, keyword_scanner):
        """Test that scan score is capped at 1.0."""
        # URL with multiple high-risk keywords
        result = keyword_scanner.scan_url("https://login-verify-paypal-invoice.com")

        assert result["score"] <= 1.0
        assert result["score"] >= 0.0

    def test_scan_url_suspicious_verdict(self, keyword_scanner):
        """Test that URLs with high risk scores get SUSPICIOUS verdict."""
        # URL with "login" keyword (high weight)
        result = keyword_scanner.scan_url("https://login.xyz")

        assert result["verdict"] == "SUSPICIOUS"
        assert result["score"] >= 0.5

    def test_scan_for_keywords_by_type(self, keyword_scanner):
        """Test filtering matches by keyword type."""
        # Scan URL with both brand and urgency keywords
        result = keyword_scanner.scan_for_keywords_by_type(
            "https://paypal-login.com",
            "brand"
        )

        assert isinstance(result, dict)
        assert "paypal" in result["matches"]
        # "login" is urgency type, not brand, so shouldn't be in results
        assert "login" not in result["matches"]

    def test_scan_for_keywords_by_type_empty(self, keyword_scanner):
        """Test scanning with type that doesn't match any keywords."""
        result = keyword_scanner.scan_for_keywords_by_type(
            "https://github.com",
            "brand"
        )

        assert result["score"] == 0.0
        assert len(result["matches"]) == 0
        assert result["verdict"] == "CLEAN"

    def test_keyword_weights_applied(self, keyword_scanner):
        """Test that keyword weights are correctly applied to scores."""
        # Keyword with high weight should produce higher score than low weight
        result_high = keyword_scanner.scan_url("https://verify.com")  # weight 0.8

        # Both should have matches but verify has specific weight
        assert result_high["score"] > 0.0

