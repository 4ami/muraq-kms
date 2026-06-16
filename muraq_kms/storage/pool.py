from muraq_kms.storage.config import StorageConfig
from muraq_kms.storage.sqlite import SQLiteStorage
from muraq_kms.storage.async_wrapper import AsyncSQLiteStorage

class StoragePool:
    """
    Coordinates access to synchronous and asynchronous storage providers.
    Does NOT hold domain-specific SQL queries.
    """
    def __init__(self, config:StorageConfig) -> None:
        self.config = config
        self._sync = SQLiteStorage(config=config)
        self._async = AsyncSQLiteStorage(self._sync)
    
    @property
    def sync_backend(self) -> SQLiteStorage:
        return self._sync
    
    @property
    def async_backend(self) -> AsyncSQLiteStorage:
        return self._async
    
    async def close_async(self) -> None:
        await self._async.close()

    def close_sync(self) -> None:
        self._sync.close()
        