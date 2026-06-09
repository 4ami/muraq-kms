from muraq_kms.storage.config import StorageConfig
from muraq_kms.storage.migrate import MigrationRunner
from muraq_kms.storage.sqlite import SQLiteStorage

__all__ = ["StorageConfig", "MigrationRunner", "SQLiteStorage"]


# def migrate_pending(config: StorageConfig | None = None) -> int:
#     """Apply pending migrations. Call from init/daemon bootstrap only."""
#     cfg = config or StorageConfig.from_env()
#     runner = MigrationRunner(cfg.db_path)
#     try:
#         return runner.upgrade()
#     finally:
#         runner.close()
