import sqlite3

_ROTATION_JOBS_SCHEMA = """
CREATE TABLE IF NOT EXISTS rotation_jobs (
_id INTEGER PRIMARY KEY AUTOINCREMENT,
logical_key_id INTEGER UNIQUE NOT NULL,
interval_days INTEGER NOT NULL DEFAULT 90,
last_run TIMESTAMP,
next_run TIMESTAMP NOT NULL,
FOREIGN KEY (logical_key_id) REFERENCES logical_keys (_id) ON DELETE CASCADE
);
"""

def upgrade(conn:sqlite3.Connection) -> None:
    conn.execute(_ROTATION_JOBS_SCHEMA)
    