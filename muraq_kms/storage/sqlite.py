import sqlite3
import threading
from contextlib import contextmanager
from typing import Any, Iterator, Literal
from muraq_kms.storage.config import StorageConfig

_DOMAIN_LITERAL = Literal["keys", "audit", "recovery", "state"]

class SQLiteStorage:
    def __init__(self, config: StorageConfig) -> None:
        self._config = config
        self._local = threading.local()

    @property
    def config(self) -> StorageConfig:
        return self._config
    
    def _get_conns(self) -> dict[str, sqlite3.Connection | None]:
        if not hasattr(self._local, "conns"):
            self._local.conns = {
                "keys": None,
                "audit": None,
                "recovery": None,
                "state": None
            }
        return self._local.conns
    
    def connection(self, domain:_DOMAIN_LITERAL = "keys") -> sqlite3.Connection:
        """
        Returns or creates a connection handle for a specific domain.
        Defaults to 'keys' to keep existing test cases and queries compatible.
        """
        conns = self._get_conns()
        if conns[domain] is None:
            if domain == "keys":
                path = self._config.db_path
            elif domain == "audit":
                path = self._config.audit_db_path
            elif domain == "state":
                path = self._config.state_db_path
            else:
                path = self._config.recovery_db_path

            path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(path, check_same_thread=False)
            self._configure(conn)
            conns[domain] = conn
            
        return conns[domain]

    def _configure(self, conn: sqlite3.Connection) -> None:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")

    @contextmanager
    def transaction(self, domain:_DOMAIN_LITERAL = "keys") -> Iterator[sqlite3.Connection]:
        with self.connection(domain) as conn:
            yield conn

    def close(self) -> None:
        if hasattr(self._local, "conns"):
            for domain, conn in self._local.conns.items():
                if conn is not None:
                    conn.close()
            self._local.conns = {
                "keys": None,
                "audit": None,
                "recovery": None,
                "state": None
            }

    def execute(self, sql: str, params: tuple[Any, ...] = (), domain:_DOMAIN_LITERAL = "keys") -> sqlite3.Cursor:
        return self.connection(domain).execute(sql, params)

    def fetchone(self, sql: str, params: tuple[Any, ...] = (), domain:_DOMAIN_LITERAL = "keys") -> tuple[Any, ...] | None:
        return self.execute(sql, params, domain).fetchone()

    def fetchall(self, sql: str, params: tuple[Any, ...] = (), domain:_DOMAIN_LITERAL = "keys") -> list[tuple[Any, ...]]:
        return self.execute(sql, params, domain).fetchall()