import sqlite3

_RECOVERY_SCHEMA = """
CREATE TABLE IF NOT EXISTS recovery_archive (
    _id TEXT PRIMARY KEY,
    key_version_kid TEXT NOT NULL,
    payload TEXT NOT NULL,
    archived_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    retention_expires_at TIMESTAMP NOT NULL,
    shred_confirmed INTEGER DEFAULT 0
);
"""

def upgrade(conn:sqlite3.Connection) -> None:
    conn.execute(_RECOVERY_SCHEMA)