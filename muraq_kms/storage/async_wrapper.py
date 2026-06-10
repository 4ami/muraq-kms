import asyncio
from typing import Any, Literal
from muraq_kms.storage.sqlite import SQLiteStorage


class AsyncSQLiteStorage:
    def __init__(self, storage: SQLiteStorage) -> None:
        self._storage = storage

    @property
    def storage(self) -> SQLiteStorage:
        return self._storage

    async def fetchone(
        self, sql: str, params: tuple[Any, ...] = (), domain: Literal["keys", "audit", "recovery", "state"] = "keys"
    ) -> tuple[Any, ...] | None:
        return await asyncio.to_thread(self._storage.fetchone, sql, params, domain)

    async def fetchall(
        self, sql: str, params: tuple[Any, ...] = (), domain: Literal["keys", "audit", "recovery", "state"] = "keys"
    ) -> list[tuple[Any, ...]]:
        return await asyncio.to_thread(self._storage.fetchall, sql, params, domain)

    async def execute(
        self, sql: str, params: tuple[Any, ...] = (), domain: Literal["keys", "audit", "recovery", "state"] = "keys"
    ) -> None:
        def _run() -> None:
            with self._storage.transaction(domain=domain) as conn:
                conn.execute(sql, params)

        await asyncio.to_thread(_run)

    async def get_active_kid(self, logical_key_name: str) -> str | None:
        return await asyncio.to_thread(self._storage.get_active_kid, logical_key_name)

    async def append_audit_entry(
        self,
        timestamp: str,
        action: str,
        actor: str,
        details: str,
        status: str,
        previous_hash: str,
        entry_hash: str,
    ) -> None:
        await asyncio.to_thread(
            self._storage.append_audit_entry,
            timestamp,
            action,
            actor,
            details,
            status,
            previous_hash,
            entry_hash,
        )

    async def close(self) -> None:
        await asyncio.to_thread(self._storage.close)
