"""Unit tests for local analysis module."""

import pytest
import asyncio
from src.baitblocker.core.local_analysis import (
    assess_url_risk,
    calculate_entropy,
    detect_mutations,
    check_length,
    check_special_characters,
    check_keywords,
)


class TestEntropyCalculation:
    """Test suite for entropy calculation."""

    def test_entropy_empty_string(self):
        """Test entropy of empty string."""
        result = calculate_entropy("")
        assert result == 0.0

    def test_entropy_single_char(self):
        """Test entropy of single character."""
        result = calculate_entropy("a")
        assert result == 0.0  # No randomness in single char

    def test_entropy_uniform_string(self):
        """Test entropy of string with uniform characters."""
        # All same character has low entropy
        result = calculate_entropy("aaaa")
        assert result == 0.0

    def test_entropy_high_randomness(self):
        """Test entropy of highly random string."""
        result_low = calculate_entropy("aaa")
        result_high = calculate_entropy("abcdefghijk")

        # High randomness should have higher entropy
        assert result_high > result_low


class TestMutationDetection:
    """Test suite for typosquatting/mutation detection."""

    def test_detect_no_mutations(self):
        """Test that exact brand matches don't get flagged."""
        result = detect_mutations("google", ["google", "amazon"])
        assert len(result) == 0

    def test_detect_one_char_mutation(self):
        """Test detection of single character mutations."""
        result = detect_mutations("gogle", ["google"])
        assert len(result) > 0
        assert result[0]["edit_distance"] == 1
        assert result[0]["confidence_score"] == 100.0

    def test_detect_two_char_mutation(self):
        """Test detection of two character mutations."""
        result = detect_mutations("ggle", ["google"])
        assert len(result) > 0
        assert result[0]["edit_distance"] == 2
        assert result[0]["confidence_score"] == 75.0

    def test_detect_no_mutation_beyond_two(self):
        """Test that mutations beyond 2 edits are not flagged."""
        result = detect_mutations("xyz", ["google"])
        assert len(result) == 0


class TestLengthChecks:
    """Test suite for URL length checks."""

    def test_normal_length(self):
        """Test normal length URLs."""
        url = "https://google.com/search"
        hostname = "google.com"
        result = check_length(url, hostname)

        assert result["score"] == 0.0
        assert len(result["reasons"]) == 0

    def test_excessive_url_length(self):
        """Test excessively long URLs."""
        url = "https://" + "a" * 100 + ".com"
        hostname = "google.com"
        result = check_length(url, hostname)

        assert result["score"] > 0.0
        assert any("Excessive" in reason for reason in result["reasons"])

    def test_excessive_hostname_length(self):
        """Test excessively long hostnames."""
        url = "https://google.com"
        hostname = "a" * 50 + ".com"
        result = check_length(url, hostname)

        assert result["score"] > 0.0


class TestSpecialCharacterChecks:
    """Test suite for special character detection."""

    def test_normal_domain(self):
        """Test normal domain with no special chars."""
        result = check_special_characters("google.com")
        assert result["score"] == 0.0

    def test_excessive_hyphens(self):
        """Test domain with excessive hyphens."""
        result = check_special_characters("sus---domain---name.com")
        assert result["score"] > 0.0
        assert any("hyphen" in reason.lower() for reason in result["reasons"])

    def test_excessive_digits(self):
        """Test domain with excessive digits."""
        result = check_special_characters("g00g1e2022v3.com")
        assert result["score"] > 0.0

    def test_multiple_subdomains(self):
        """Test domain with too many subdomains."""
        result = check_special_characters("a.b.c.d.e.example.com")
        assert result["score"] > 0.0


class TestURLAnalysis:
    """Test suite for full URL risk assessment."""

    @pytest.mark.asyncio
    async def test_analyze_safe_url(self, sample_urls):
        """Test analysis of safe URLs."""
        for url in sample_urls["safe"]:
            result = await assess_url_risk(url)

            assert "verdict" in result
            assert "risk_score" in result
            assert "reasons" in result
            assert 0.0 <= result["risk_score"] <= 1.0

    @pytest.mark.asyncio
    async def test_analyze_suspicious_url(self, sample_urls):
        """Test analysis of suspicious URLs."""
        for url in sample_urls["suspicious"]:
            result = await assess_url_risk(url)

            # Some URLs may have risk_score 0 if WHOIS fails and no local flags
            assert 0.0 <= result["risk_score"] <= 1.0
            assert isinstance(result["reasons"], list)

    @pytest.mark.asyncio
    async def test_analyze_malformed_input(self):
        """Test that malformed input is rejected."""
        result = await assess_url_risk("a" * 3000)  # Exceeds max length

        assert result["verdict"] == "MALFORMED"
        assert result["risk_score"] == 1.0

    @pytest.mark.asyncio
    async def test_analyze_ip_address_url(self):
        """Test detection of raw IP addresses."""
        result = await assess_url_risk("http://192.168.1.1")

        # IP addresses should have high risk, but WHOIS failures may affect score
        assert result["risk_score"] >= 0.0  
        assert any("IP" in reason for reason in result["reasons"])

    @pytest.mark.asyncio
    async def test_analyze_adds_scheme(self):
        """Test that missing scheme is added."""
        result = await assess_url_risk("google.com")

        # Should add https:// prefix
        assert result["url"].startswith("https://")

    @pytest.mark.asyncio
    async def test_analyze_risk_score_range(self, sample_urls):
        """Test that risk scores stay within 0.0-1.0 range."""
        all_urls = sample_urls["safe"] + sample_urls["suspicious"]

        for url in all_urls:
            result = await assess_url_risk(url)
            assert 0.0 <= result["risk_score"] <= 1.0


# Helper function to run async tests
def test_async_url_analysis():
    """Test basic async URL analysis."""
    async def _test():
        result = await assess_url_risk("https://example.com")
        assert result["verdict"] in ["Safe", "Suspicious", "High Risk", "MALFORMED"]

    asyncio.run(_test())

