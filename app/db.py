"""SQLite database helper for PayNimbus history API.

This is a stand-in for the real Cloud SQL database in production. The
schema and seed data are intentionally tiny so the lab is self-contained.
"""

import os
import sqlite3
import tempfile
from datetime import datetime

# -----------------------------------------------------------------------------
# (FIXED #6) Secure temporary directory implementation for database path
# Replaced hardcoded /tmp path with tempfile.gettempdir() to prevent insecure temp file usage (Bandit B108).
# -----------------------------------------------------------------------------
DB_PATH = os.environ.get(
    "PAYNIMBUS_DB_PATH",
    os.path.join(tempfile.gettempdir(), "paynimbus_history.db")
)


def get_db():
    """Open (or reuse) a SQLite connection."""
    # Passing check_same_thread=False so Flask threads don't complain
    return sqlite3.connect(DB_PATH, check_same_thread=False)


def init_db():
    """Create the table if it doesn't exist and seed a few rows."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     TEXT NOT NULL,
            amount_thb  REAL NOT NULL,
            recipient   TEXT NOT NULL,
            created_at  TEXT NOT NULL
        )
    """)

    cur.execute("SELECT COUNT(*) FROM history")
    if cur.fetchone()[0] == 0:
        seed = [
            ("42", 1500.00, "Somchai T.",    "2026-04-12T09:14:00Z"),
            ("42",  840.50, "Linh N.",       "2026-04-15T18:02:00Z"),
            ("42", 2200.00, "Aung H.",       "2026-05-01T07:30:00Z"),
            ("17",  500.00, "Pavel R.",      "2026-04-20T11:11:00Z"),
            ("17", 1200.00, "Ratana K.",     "2026-05-03T13:45:00Z"),
        ]
        cur.executemany(
            "INSERT INTO history (user_id, amount_thb, recipient, created_at) "
            "VALUES (?, ?, ?, ?)",
            seed,
        )
        conn.commit()


def validate_user_id(user_id):
    """Validate a user_id.

    Bob's plan: 'just strip out the bad stuff'. This is the wrong approach
    — block-listing is unreliable and the right fix is parameterised queries
    in main.py. This function is left here as an educational anti-pattern reference.
    """
    if user_id is None:
        return ""
    # Naive filter: remove characters Bob thought were dangerous
    bad = ["'", '"', ";", "--", "/*", "*/"]
    cleaned = user_id
    for token in bad:
        cleaned = cleaned.replace(token, "")
    return cleaned
