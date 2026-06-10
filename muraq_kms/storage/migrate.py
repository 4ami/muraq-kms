import importlib.util
import os
import sqlite3
from pathlib import Path
from typing import Literal


class MigrationRunner:
    def __init__(self, db_path: Path, domain: Literal["keys_db", "recovery_db", "audit_db", "state_db"]) -> None:
        self._db_path = db_path
        self._domain = domain
        self._conn: sqlite3.Connection | None = None
        self._MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations" / self._domain

    def _connection(self) -> sqlite3.Connection:
        if self._conn is None:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(self._db_path)
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def ensure_ledger(self) -> None:
        conn = self._connection()
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                feature_version TEXT PRIMARY KEY,
                applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        conn.commit()

    def _get_features(self) -> list[str]:
        if not self._MIGRATIONS_DIR.exists():
            return []
        folders = [
            d
            for d in os.listdir(self._MIGRATIONS_DIR)
            if (self._MIGRATIONS_DIR / d).is_dir() and not d.startswith("__")
        ]
        return sorted(folders)

    def _applied(self) -> set[str]:
        conn = self._connection()
        cursor = conn.execute("SELECT feature_version FROM schema_migrations;")
        return {row[0] for row in cursor.fetchall()}

    def pending(self) -> list[str]:
        self.ensure_ledger()
        return [f for f in self._get_features() if f not in self._applied()]

    def _run_script(
        self,
        conn: sqlite3.Connection,
        feature: str,
        type_: Literal["upgrade", "downgrade"] = "upgrade",
    ) -> None:
        file_path = self._MIGRATIONS_DIR / feature / f"{type_}.py"
        if not file_path.exists():
            raise FileNotFoundError(f"Missing {type_}.py in feature {feature}")

        module_name = f"muraq_migration_{feature}_{type_}"
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot load migration script: {file_path}")

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        if not hasattr(module, type_):
            raise AttributeError(
                f"Script {file_path} must implement `{type_}(conn: sqlite3.Connection)`."
            )
        getattr(module, type_)(conn)

    def upgrade(self) -> int:
        """Apply all pending migrations. Returns count applied."""
        self.ensure_ledger()
        conn = self._connection()
        applied = self._applied()
        count = 0

        for folder in self._get_features():
            if folder in applied:
                continue
            with conn:
                self._run_script(conn, folder, "upgrade")
                conn.execute(
                    "INSERT INTO schema_migrations (feature_version) VALUES (?);",
                    (folder,),
                )
            count += 1

        return count

    def downgrade_one(self) -> str | None:
        """Reverse the most recently applied migration (dev only)."""
        self.ensure_ledger()
        conn = self._connection()
        row = conn.execute(
            "SELECT feature_version FROM schema_migrations ORDER BY applied_at DESC LIMIT 1;"
        ).fetchone()

        if row is None:
            return None

        feature = row[0]
        with conn:
            self._run_script(conn, feature, "downgrade")
            conn.execute(
                "DELETE FROM schema_migrations WHERE feature_version = ?;",
                (feature,),
            )
        return feature
