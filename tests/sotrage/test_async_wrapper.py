import asyncio
import time

import pytest

from muraq_kms.storage.async_wrapper import AsyncSQLiteStorage
from tests.sotrage.helpers import insert_key_version, insert_logical_key


@pytest.fixture
def same_thread_to_thread(monkeypatch):
    """Run to_thread calls inline so sqlite connections stay on one thread."""

    async def _run(func, *args, **kwargs):
        return func(*args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", _run)


def test_async_execute(migrated_storage, same_thread_to_thread):
    async def _run():
        async_storage = AsyncSQLiteStorage(migrated_storage)
        await async_storage.execute("SELECT 1;")
        row = await async_storage.fetchone("SELECT 1;")
        await async_storage.close()
        return row

    assert asyncio.run(_run()) == (1,)

def test_async_wrapper_completes_quickly(migrated_storage, same_thread_to_thread):
    async def _run():
        async_storage = AsyncSQLiteStorage(migrated_storage)
        await async_storage.fetchone("SELECT 1;")
        await async_storage.close()

    start = time.monotonic()
    asyncio.run(_run())
    assert time.monotonic() - start < 1.0
