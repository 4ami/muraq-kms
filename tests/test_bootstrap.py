from core.bootstrap import bootstrap_storage
from tests.conftest import KEYS_DB_EXPECTED_MIGRATIONS


def test_bootstrap_creates_layout_and_migrations(storage_config):
    storage = bootstrap_storage(storage_config)
    try:
        for subdir in ("audit", "recovery", "backups"):
            assert (storage_config.base_dir / subdir).is_dir()

        rows = storage.fetchall(
            "SELECT feature_version FROM schema_migrations ORDER BY feature_version;"
        )
        assert [row[0] for row in rows] == KEYS_DB_EXPECTED_MIGRATIONS
    finally:
        storage.close()


def test_bootstrap_second_call_is_idempotent(storage_config):
    first = bootstrap_storage(storage_config)
    first.close()

    second = bootstrap_storage(storage_config)
    try:
        count = second.fetchone("SELECT COUNT(*) FROM schema_migrations;")[0]
        assert count == len(KEYS_DB_EXPECTED_MIGRATIONS)
    finally:
        second.close()
