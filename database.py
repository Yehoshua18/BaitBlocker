import sqlite3

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


def get_all_keywords() -> list[tuple[str, float]]:
    """Retrieves all dangerous keywords and their associated weights."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT keyword, risk_weight FROM unsafe_keywords")
    rows = cursor.fetchall()
    conn.close()
    return rows  # Returns a list of tuples: [('login', 0.5), ...]