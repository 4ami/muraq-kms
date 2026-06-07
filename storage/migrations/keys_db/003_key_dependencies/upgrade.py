import sqlite3

_KEY_DEPENDENCIES_SCHEMA = """
CREATE TABLE IF NOT EXISTS key_dependencies (
    _id TEXT PRIMARY KEY,
    ciphertext_id TEXT NOT NULL,
    ref_kid TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('coupled', 'migrating', 'orphan', 'quarantined')),
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(ref_kid) REFERENCES key_versions(kid)
);
"""

_REF_KID_IDX = "CREATE INDEX IF NOT EXISTS idx_ref_kid ON key_dependencies (ref_kid);"

def upgrade(conn:sqlite3.Connection) -> None:
    conn.execute(_KEY_DEPENDENCIES_SCHEMA)
    conn.execute(_REF_KID_IDX)
    