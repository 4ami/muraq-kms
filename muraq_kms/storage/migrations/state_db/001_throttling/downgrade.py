import sqlite3

def downgrade(conn:sqlite3.Connection) -> None:
    conn.execute("DROP TABLE IF EXISTS throttling_state;")