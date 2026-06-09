import sqlite3
from contextlib import contextmanager
from typing import Any, Iterator, Literal
from muraq_kms.storage.config import StorageConfig


class SQLiteStorage:
    def __init__(self, config: StorageConfig) -> None:
        self._config = config
        self._conns: dict[str, sqlite3.Connection | None] = {
            "keys": None,
            "audit": None,
            "recovery": None
        }

    @property
    def config(self) -> StorageConfig:
        return self._config
    
    def connection(self, domain: Literal["keys", "audit", "recovery"] = "keys") -> sqlite3.Connection:
        """
        Returns or creates a connection handle for a specific domain.
        Defaults to 'keys' to keep existing test cases and queries compatible.
        """
        if self._conns[domain] is None:
            if domain == "keys":
                path = self._config.db_path
            elif domain == "audit":
                path = self._config.audit_db_path
            else:
                path = self._config.recovery_db_path

            path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(path)
            self._configure(conn)
            self._conns[domain] = conn
            
        return self._conns[domain]

    def _configure(self, conn: sqlite3.Connection) -> None:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")

    @contextmanager
    def transaction(self, domain: Literal["keys", "audit", "recovery"] = "keys") -> Iterator[sqlite3.Connection]:
        with self.connection(domain) as conn:
            yield conn

    def close(self) -> None:
        for domain, conn in self._conns.items():
            if conn is not None:
                conn.close()
                self._conns[domain] = None

    def execute(self, sql: str, params: tuple[Any, ...] = (), domain: Literal["keys", "audit", "recovery"] = "keys") -> sqlite3.Cursor:
        return self.connection(domain).execute(sql, params)

    def fetchone(self, sql: str, params: tuple[Any, ...] = (), domain: Literal["keys", "audit", "recovery"] = "keys") -> tuple[Any, ...] | None:
        return self.execute(sql, params, domain).fetchone()

    def fetchall(self, sql: str, params: tuple[Any, ...] = (), domain: Literal["keys", "audit", "recovery"] = "keys") -> list[tuple[Any, ...]]:
        return self.execute(sql, params, domain).fetchall()

    def get_active_kid(self, logical_key_name: str) -> str | None:
        row = self.fetchone(
            """
            SELECT kv.kid
            FROM key_versions kv
            JOIN logical_keys lk ON lk._id = kv.logical_key_id
            WHERE lk.name = ? AND kv.state = 'active'
            LIMIT 1;
            """,
            (logical_key_name,),
        )
        return row[0] if row else None

    def list_versions(self, logical_key_name: str) -> list[tuple[Any, ...]]:
        return self.fetchall(
            """
            SELECT kv.kid, kv.version, kv.state, kv.algorithm, kv.created_at
            FROM key_versions kv
            JOIN logical_keys lk ON lk._id = kv.logical_key_id
            WHERE lk.name = ?
            ORDER BY kv.version;
            """,
            (logical_key_name,),
        )

    def register_dependency(
        self,
        dependency_id: str,
        ciphertext_id: str,
        ref_kid: str,
        status: str = "coupled",
    ) -> None:
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO key_dependencies (_id, ciphertext_id, ref_kid, status)
                VALUES (?, ?, ?, ?);
                """,
                (dependency_id, ciphertext_id, ref_kid, status),
            )

    def mark_migrating(self, ciphertext_id: str) -> None:
        with self.transaction() as conn:
            conn.execute(
                """
                UPDATE key_dependencies
                SET status = 'migrating'
                WHERE ciphertext_id = ?;
                """,
                (ciphertext_id,),
            )

    def append_audit_entry(
        self,
        timestamp: str,
        action: str,
        actor: str,
        details: str,
        status: str,
        previous_hash: str,
        entry_hash: str,
    ) -> None:
        with self.transaction(domain="audit") as conn:
            conn.execute(
                """
                INSERT INTO audit_log
                    (timestamp, action, actor, details, status, previous_hash, hash)
                VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (timestamp, action, actor, details, status, previous_hash, entry_hash),
            )
