import pytest

from muraq_kms.storage.config import StorageConfig
from muraq_kms.storage.migrate import MigrationRunner
from muraq_kms.storage.sqlite import SQLiteStorage

KEYS_DB_EXPECTED_MIGRATIONS = [
    "001_keys",
    "002_rotation",
    "003_key_dependencies",
]

AUDIT_DB_EXPECTED_MIGRATIONS = [
    "001_audit",
    "002_audit_indexes",
]

RECOVERY_DB_EXPECTED_MIGRATIONS = [
    "001_recovery",
]


@pytest.fixture
def storage_config(tmp_path) -> StorageConfig:
    return StorageConfig(tmp_path / "kms")


@pytest.fixture
def migrated_storage(storage_config: StorageConfig) -> SQLiteStorage:
    runner = MigrationRunner(storage_config.db_path, domain="keys_db")
    audit_runner = MigrationRunner(storage_config.audit_db_path, domain="audit_db")
    recovery_runner = MigrationRunner(storage_config.recovery_db_path, domain="recovery_db")
    try:
        runner.upgrade()
        audit_runner.upgrade()
        recovery_runner.upgrade()
    finally:
        runner.close()
        audit_runner.close()
        recovery_runner.close()

    storage = SQLiteStorage(storage_config)
    yield storage
    storage.close()