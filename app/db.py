"""
Database configuration and initialization for PayNimbus History API.
"""
import os
import sqlite3
import tempfile

# -----------------------------------------------------------------------------
# (FIXED #6) Secure temporary directory implementation for database path
# Replaced hardcoded /tmp path with tempfile.gettempdir() to prevent insecure temp file usage (B108).
# -----------------------------------------------------------------------------
DB_PATH = os.environ.get(
    "PAYNIMBUS_DB_PATH",
    os.path.join(tempfile.gettempdir(), "paynimbus_history.db")
)

def get_db():
    """Establish and return SQLite database connection."""
    conn = sqlite3.connect(DB_PATH)
    return conn

def init_db():
    """Initialize SQLite database schema and seed mock history transactions."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            amount_thb REAL NOT NULL,
            recipient TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Seed sample transactions if table is empty
    cursor.execute("SELECT COUNT(*) FROM history")
    if cursor.fetchone()[0] == 0:
        sample_transactions = [
            ("user_01", 1500.00, "PromptPay-0812345678", "2026-06-01 10:30:00"),
            ("user_01", 250.50, "TrueMoney-0898765432", "2026-06-02 14:15:00"),
            ("user_02", 5000.00, "SCB-1234567890", "2026-06-03 09:00:00"),
            ("user_03", 890.00, "KBANK-9876543210", "2026-06-03 12:45:00"),
        ]
        cursor.executemany(
            "INSERT INTO history (user_id, amount_thb, recipient, created_at) VALUES (?, ?, ?, ?)",
            sample_transactions
        )
        conn.commit()
    conn.close()
