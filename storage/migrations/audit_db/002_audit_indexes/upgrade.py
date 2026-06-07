import sqlite3

_AUDIT_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log (timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log (action);",
    "CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log (actor);",
]


def upgrade(conn: sqlite3.Connection) -> None:
    for stmt in _AUDIT_INDEXES:
        conn.execute(stmt)
