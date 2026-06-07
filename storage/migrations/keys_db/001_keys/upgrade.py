import sqlite3


_LOGICAL_KEYS_SCHEMA = """
CREATE TABLE IF NOT EXISTS logical_keys (
_id INTEGER PRIMARY KEY AUTOINCREMENT,
name TEXT NOT NULL UNIQUE,
purpose TEXT NOT NULL CHECK (purpose IN ('encryption', 'signing', 'wrapping')),
description TEXT,
exportable INTEGER NOT NULL DEFAULT 0,
borrowable INTEGER NOT NULL DEFAULT 0,
borrow_ttl_seconds INTEGER DEFAULT 30,
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""


_KEY_VERSIONS_SCHEMA = """
CREATE TABLE IF NOT EXISTS key_versions (
kid TEXT PRIMARY KEY,
logical_key_id INTEGER NOT NULL,
version INTEGER NOT NULL,
state TEXT NOT NULL CHECK (
    state IN (
        'active', 'deprecated', 'revoked', 'archived', 'destroyed', 'eligible_for_destroy'
    )
),
algorithm TEXT NOT NULL,
raw_material TEXT NOT NULL,
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
activated_at TIMESTAMP,
revoked_at TIMESTAMP,
archived_at TIMESTAMP,
destroyed_at TIMESTAMP,
FOREIGN KEY (logical_key_id) REFERENCES logical_keys(_id) ON DELETE CASCADE
);
"""

_KEY_VERSIONS_LOGICAL_KEY_IDX = """
CREATE INDEX IF NOT EXISTS idx_key_versions_logical_key_id 
ON key_versions (logical_key_id);
"""

_ONE_ACTIVE_PER_LOGICAL_KEY = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_per_logical_key
ON key_versions (logical_key_id)
WHERE state = 'active';
"""

def upgrade(conn:sqlite3.Connection) -> None:
    conn.execute(_LOGICAL_KEYS_SCHEMA)
    conn.execute(_KEY_VERSIONS_SCHEMA)
    conn.execute(_KEY_VERSIONS_LOGICAL_KEY_IDX)
    conn.execute(_ONE_ACTIVE_PER_LOGICAL_KEY)
