import asyncio
import time

import pytest

from storage.async_wrapper import AsyncSQLiteStorage
from tests.sotrage.helpers import insert_key_version, insert_logical_key


@pytest.fixture
def same_thread_to_thread(monkeypatch):
    """Run to_thread calls inline so sqlite connections stay on one thread."""

    async def _run(func, *args, **kwargs):
        return func(*args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", _run)


def test_async_get_active_kid(migrated_storage, same_thread_to_thread):
    logical_key_id = insert_logical_key(migrated_storage, name="async-key")
    insert_key_version(
        migrated_storage, logical_key_id, "kid-async", version=1, state="active"
    )

    async def _run():
        async_storage = AsyncSQLiteStorage(migrated_storage)
        kid = await async_storage.get_active_kid("async-key")
        await async_storage.close()
        return kid

    assert asyncio.run(_run()) == "kid-async"


def test_async_execute(migrated_storage, same_thread_to_thread):
    async def _run():
        async_storage = AsyncSQLiteStorage(migrated_storage)
        await async_storage.execute("SELECT 1;")
        row = await async_storage.fetchone("SELECT 1;")
        await async_storage.close()
        return row

    assert asyncio.run(_run()) == (1,)


def test_async_append_audit_entry(migrated_storage, same_thread_to_thread):
    async def _run():
        async_storage = AsyncSQLiteStorage(migrated_storage)
        await async_storage.append_audit_entry(
            timestamp="2026-06-06T12:00:00Z",
            action="key.read",
            actor="svc",
            details="{}",
            status="SUCCESS",
            previous_hash="prev",
            entry_hash="hash",
        )
        row = await async_storage.fetchone(
            "SELECT action FROM audit_log WHERE action = ?;", ("key.read",),
            domain="audit"
        )
        await async_storage.close()
        return row

    assert asyncio.run(_run()) == ("key.read",)


def test_async_wrapper_completes_quickly(migrated_storage, same_thread_to_thread):
    async def _run():
        async_storage = AsyncSQLiteStorage(migrated_storage)
        await async_storage.fetchone("SELECT 1;")
        await async_storage.close()

    start = time.monotonic()
    asyncio.run(_run())
    assert time.monotonic() - start < 1.0
