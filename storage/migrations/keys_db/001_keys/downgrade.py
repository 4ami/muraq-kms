import sqlite3

def downgrade(conn:sqlite3.Connection) -> None:
    conn.execute("DROP INDEX IF EXISTS idx_one_active_per_logical_key;")
    conn.execute("DROP INDEX IF EXISTS idx_key_versions_logical_key_id;")
    conn.execute("DROP TABLE IF EXISTS key_versions;")
    conn.execute("DROP TABLE IF EXISTS logical_keys;")