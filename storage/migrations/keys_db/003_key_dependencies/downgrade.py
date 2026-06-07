import sqlite3

def downgrade(conn:sqlite3.Connection) -> None:
    conn.execute("DROP INDEX IF EXISTS idx_ref_kid;")
    conn.execute("DROP TABLE IF EXISTS key_dependencies;")