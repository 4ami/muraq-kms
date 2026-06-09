import sqlite3

_AUDIT_LOG_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP NOT NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    details TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('SUCCESS', 'DENIED', 'FAILED')),
    previous_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
"""

def upgrade(conn:sqlite3.Connection) -> None:
    conn.execute(_AUDIT_LOG_SCHEMA)