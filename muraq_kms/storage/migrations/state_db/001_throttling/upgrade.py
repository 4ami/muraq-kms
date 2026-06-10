import sqlite3

_THROTTLING_STATE_SCHEMA = """
CREATE TABLE IF NOT EXISTS throttling_state (
id INTEGER PRIMARY KEY CHECK (id = 1),
failed_attempts INTEGER NOT NULL,
locked_until_epoch REAL NOT NULL,
tamper_signature TEXT NOT NULL
);
"""

_INIT_THROTTLE = """
INSERT OR IGNORE INTO throttling_state (id, failed_attempts, locked_until_epoch, tamper_signature)
VALUES (1, 0, 0.0, 'INITIALIZED');
"""

def upgrade(conn:sqlite3.Connection) -> None:
    conn.execute(_THROTTLING_STATE_SCHEMA)
    conn.execute(_INIT_THROTTLE)
