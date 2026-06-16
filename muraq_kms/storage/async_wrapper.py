import asyncio
import sqlite3
from typing import Any, AsyncIterator
from muraq_kms.storage.sqlite import SQLiteStorage, _DOMAIN_LITERAL
from contextlib import asynccontextmanager

class AsyncSQLiteStorage:
    def __init__(self, storage: SQLiteStorage) -> None:
        self._storage = storage

    @property
    def storage(self) -> SQLiteStorage:
        return self._storage
    
    @asynccontextmanager
    async def transaction(self, domain:_DOMAIN_LITERAL) -> AsyncIterator[SQLiteStorage]:
        conn = await asyncio.to_thread(self._storage.connection, domain)

        await asyncio.to_thread(conn.execute, "BEGIN")
        try:
            yield self.storage
            await asyncio.to_thread(conn.commit)
        except Exception:
            await asyncio.to_thread(conn.rollback)
            raise

    async def fetchone(self, sql: str, params: tuple[Any, ...] = (), domain:_DOMAIN_LITERAL = "keys") -> tuple[Any, ...] | None:
        return await asyncio.to_thread(self._storage.fetchone, sql, params, domain)

    async def fetchall(self, sql: str, params: tuple[Any, ...] = (), domain:_DOMAIN_LITERAL = "keys") -> list[tuple[Any, ...]]:
        return await asyncio.to_thread(self._storage.fetchall, sql, params, domain)

    async def execute(self, sql: str, params: tuple[Any, ...] = (), domain:_DOMAIN_LITERAL = "keys") -> sqlite3.Cursor:
        return await asyncio.to_thread(self._storage.execute, sql, params, domain)

    async def close(self) -> None:
        await asyncio.to_thread(self._storage.close)