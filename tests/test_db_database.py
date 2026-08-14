"""Unit tests for database module."""

import pytest
from src.baitblocker.db.database import (
    init_db,
    get_all_keywords,
    get_by_type,
    add_single_keyword,
    add_bulk_keywords,
)


class TestDatabaseOperations:
    """Test suite for database CRUD operations."""

    def test_init_db(self, test_db):
        """Test that database initializes with seed data."""
        keywords = get_all_keywords()
        assert len(keywords) > 0
        # Check seed keywords exist
        keyword_names = [kw[0] for kw in keywords]
        assert "login" in keyword_names

    def test_get_all_keywords(self, test_db):
        """Test retrieving all keywords from database."""
        keywords = get_all_keywords()
        assert isinstance(keywords, list)
        assert len(keywords) > 0
        # Check tuple structure (keyword, weight)
        assert all(isinstance(kw, tuple) and len(kw) == 2 for kw in keywords)

    def test_get_by_type(self, test_db):
        """Test filtering keywords by category type."""
        brand_keywords = get_by_type("brand")
        assert isinstance(brand_keywords, list)
        assert "paypal" in brand_keywords
        assert "google" in brand_keywords

        urgency_keywords = get_by_type("urgency")
        assert "login" in urgency_keywords or "verify" in urgency_keywords
        assert "verify" in urgency_keywords

    def test_add_single_keyword_new(self, test_db):
        """Test adding a single new keyword."""
        result = add_single_keyword("malware", "security", 0.95)
        assert result is True

        keywords = get_all_keywords()
        keyword_names = [kw[0] for kw in keywords]
        assert "malware" in keyword_names

    def test_add_single_keyword_duplicate(self, test_db):
        """Test adding a duplicate keyword returns False."""
        # Add keyword first time
        add_single_keyword("ransomware", "security", 0.9)
        # Try to add same keyword again
        result = add_single_keyword("ransomware", "security", 0.9)
        assert result is False

    def test_add_bulk_keywords(self, test_db):
        """Test bulk insertion of keywords."""
        initial_count = len(get_all_keywords())

        new_keywords = [
            ("phishing", "security", 0.95),
            ("trojan", "security", 0.90),
            ("scam", "financial", 0.85),
        ]
        add_bulk_keywords(new_keywords)

        final_count = len(get_all_keywords())
        assert final_count > initial_count

    def test_add_bulk_keywords_with_duplicates(self, test_db):
        """Test bulk insertion handles duplicates gracefully."""
        # Add some keywords
        keywords = [
            ("spam", "security", 0.7),
            ("phish", "security", 0.9),
        ]
        count1 = add_bulk_keywords(keywords)

        # Add same keywords again (should be ignored)
        count2 = add_bulk_keywords(keywords)

        assert count1 > 0
        assert count2 > 0  # Count reported but not added to DB

    def test_keyword_weights(self, test_db):
        """Test that keyword weights are stored and retrieved correctly."""
        add_single_keyword("test_kw", "test_cat", 0.42)

        keywords = get_all_keywords()
        test_kw = next((kw for kw in keywords if kw[0] == "test_kw"), None)

        assert test_kw is not None
        assert test_kw[1] == 0.42

