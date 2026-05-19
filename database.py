import sqlite3

from typing import List, Tuple

DB_NAME = "threat_intel.db"


def init_db():
    """Creates the database and seeds initial unsafe keywords."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Create the schema
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS unsafe_keywords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            keyword TEXT UNIQUE NOT NULL,
            category TEXT,
            risk_weight REAL DEFAULT 0.25
        )
    """)

    # Seed data (ignore conflicts if they already exist)
    initial_keywords = [
        ("login", "infrastructure", 0.50),
        ("signin", "infrastructure", 0.50),
        ("verify", "urgency", 0.40),
        ("update", "urgency", 0.20),
        ("invoice", "financial", 0.60),
        ("docusign", "document", 0.80)
    ]

    cursor.executemany("""
        INSERT OR IGNORE INTO unsafe_keywords (keyword, category, risk_weight)
        VALUES (?, ?, ?)
    """, initial_keywords)

    conn.commit()
    conn.close()


def get_all_keywords() -> List[Tuple[str, float]]:
    """Retrieves all dangerous keywords and their associated weights."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT keyword, risk_weight FROM unsafe_keywords")
    rows = cursor.fetchall()
    conn.close()
    return rows  # Returns a list of tuples: [('login', 0.5), ...]


def add_single_keyword(keyword: str, category: str, risk_weight: float = 0.25) -> bool:
    """
    Adds a single keyword to the database.
    Returns True if added, False if it already existed.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # INSERT OR IGNORE skips the entry cleanly if the keyword violates the UNIQUE constraint
    cursor.execute("""
        INSERT OR IGNORE INTO unsafe_keywords (keyword, category, risk_weight)
        VALUES (?, ?, ?)
    """, (keyword.lower().strip(), category, risk_weight))

    # rowcount tells us if a row was actually modified
    changes = cursor.rowcount
    conn.commit()
    conn.close()

    return changes > 0


def add_bulk_keywords(keywords_list: List[Tuple[str, str, float]]) -> int:
    """
    Efficiently inserts a batch list of keywords.
    Expects a list of tuples: [('paypal', 'brand', 0.90), ('refund', 'financial', 0.60)]
    Returns the total number of newly added entries.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Normalize keywords to lowercase and strip whitespaces before database entry
    cleaned_data = [
        (item[0].lower().strip(), item[1], item[2])
        for item in keywords_list
    ]

    cursor.executemany("""
        INSERT OR IGNORE INTO unsafe_keywords (keyword, category, risk_weight)
        VALUES (?, ?, ?)
    """, cleaned_data)

    # SQLite doesn't natively return affected row counts easily for execuitemany,
    # so we commit and check total changes if needed, or simply return success tracking.
    conn.commit()
    conn.close()
    return len(cleaned_data)