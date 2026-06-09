import sqlite3

_INDEXES = [
    "idx_audit_log_timestamp",
    "idx_audit_log_action",
    "idx_audit_log_actor",
]


def downgrade(conn: sqlite3.Connection) -> None:
    for name in _INDEXES:
        conn.execute(f"DROP INDEX IF EXISTS {name};")
