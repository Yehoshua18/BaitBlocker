"""Pytest configuration and shared fixtures for BaitBlocker tests."""

import pytest

from src.baitblocker.db.database import init_db, add_bulk_keywords
from src.baitblocker.db.matcher import KeywordScanner


@pytest.fixture(scope="session")
def test_db(tmp_path_factory):
    """Create a temporary test database."""
    db_path = tmp_path_factory.mktemp("data") / "test_threat_intel.db"

    # Override DB_NAME for tests
    import src.baitblocker.db.database as db_module
    original_db = db_module.DB_NAME
    db_module.DB_NAME = str(db_path)

    # Initialize test database
    init_db()

    # Add some test keywords
    test_keywords = [
        ("login", "urgency", 0.9),
        ("verify", "urgency", 0.8),
        ("paypal", "brand", 0.9),
        ("google", "brand", 0.9),
        ("invoice", "financial", 0.8),
    ]
    add_bulk_keywords(test_keywords)

    yield db_path

    # Restore original DB_NAME
    db_module.DB_NAME = original_db


@pytest.fixture
def keyword_scanner():
    """Create a KeywordScanner instance for testing."""
    scanner = KeywordScanner()
    return scanner


@pytest.fixture
def sample_urls():
    """Provide sample URLs for testing."""
    return {
        "safe": [
            "https://google.com",
            "https://github.com",
            "https://stackoverflow.com",
        ],
        "suspicious": [
            "https://gooogle-login.xyz",
            "https://paypal-verify.xyz",
            "https://192.168.1.1:8080",
            "https://signin-paypal.club",
        ],
        "malicious": [
            "https://2h4d7x9.xyz/phishing",
            "https://admin-panel.gq",
            "https://verify-identity.tk",
        ],
    }


@pytest.fixture
def sample_emails():
    """Provide sample email texts for testing."""
    return {
        "safe": [
            "Hello, this is a confirmation for your order #12345. Thank you for shopping with us!",
            "Meeting scheduled for tomorrow at 2 PM in Conference Room B.",
        ],
        "suspicious": [
            "Urgent: Your account has been compromised. Click here immediately to verify your identity.",
            "ALERT: Unusual activity detected. Update your billing information NOW to prevent account suspension.",
            "Congratulations! You've won $1,000,000! Click here to claim your prize.",
        ],
    }

