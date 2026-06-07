from storage.config import StorageConfig
from storage.migrate import MigrationRunner
from storage.sqlite import SQLiteStorage


def bootstrap_storage(config: StorageConfig | None = None) -> SQLiteStorage:
    """
    Process-level bootstrap: ensure layout, apply pending migrations, return storage.

    Call from muraq-kms init, daemon startup, or doctor — not on bare import.
    """
    cfg = config or StorageConfig.from_env()
    cfg.ensure_layout()

    keys_runner = MigrationRunner(db_path=cfg.db_path, domain="keys_db")
    recovery_runner = MigrationRunner(db_path=cfg.recovery_db_path, domain="recovery_db")
    audit_runner = MigrationRunner(db_path=cfg.audit_db_path, domain="audit_db")
    try:
        keys_runner.upgrade()
        recovery_runner.upgrade()
        audit_runner.upgrade()
    finally:
        keys_runner.close()
        recovery_runner.close()
        audit_runner.close()

    return SQLiteStorage(cfg)
