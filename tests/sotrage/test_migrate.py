import sqlite3

import pytest

from storage.migrate import MigrationRunner
from tests.sotrage.conftest import KEYS_DB_EXPECTED_MIGRATIONS
from tests.sotrage.helpers import insert_key_version, insert_logical_key


def _ledger_features(runner: MigrationRunner) -> list[str]:
    conn = runner._connection()
    rows = conn.execute(
        "SELECT feature_version FROM schema_migrations ORDER BY feature_version;"
    ).fetchall()
    return [row[0] for row in rows]


def test_upgrade_applies_all_migrations(storage_config):
    runner = MigrationRunner(storage_config.db_path, domain="keys_db")
    try:
        applied = runner.upgrade()
        assert applied == len(KEYS_DB_EXPECTED_MIGRATIONS)
        assert _ledger_features(runner) == KEYS_DB_EXPECTED_MIGRATIONS
    finally:
        runner.close()


def test_pending_empty_after_full_upgrade(storage_config):
    runner = MigrationRunner(storage_config.db_path, domain="keys_db")
    try:
        runner.upgrade()
        assert runner.pending() == []
    finally:
        runner.close()


def test_second_upgrade_is_noop(storage_config):
    runner = MigrationRunner(storage_config.db_path, domain="keys")
    try:
        runner.upgrade()
        assert runner.upgrade() == 0
    finally:
        runner.close()


def test_upgrade_creates_core_tables(storage_config):
    runner = MigrationRunner(storage_config.db_path, domain="keys_db")
    try:
        runner.upgrade()
        conn = runner._connection()
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table';"
            ).fetchall()
        }
        assert {
            "schema_migrations",
            "logical_keys",
            "key_versions",
            "rotation_jobs",
            "key_dependencies",
        }.issubset(tables)
    finally:
        runner.close()


def test_one_active_version_per_logical_key_enforced(migrated_storage):
    logical_key_id = insert_logical_key(migrated_storage)
    insert_key_version(migrated_storage, logical_key_id, "kid-1", version=1, state="active")

    with pytest.raises(sqlite3.IntegrityError):
        insert_key_version(
            migrated_storage, logical_key_id, "kid-2", version=2, state="active"
        )


def test_eligible_for_destroy_state_allowed(migrated_storage):
    logical_key_id = insert_logical_key(migrated_storage, name="destroy-candidate")
    insert_key_version(
        migrated_storage,
        logical_key_id,
        "kid-destroy",
        version=1,
        state="eligible_for_destroy",
    )

    row = migrated_storage.fetchone(
        "SELECT state FROM key_versions WHERE kid = ?;", ("kid-destroy",)
    )
    assert row == ("eligible_for_destroy",)


def test_downgrade_one_removes_one_applied_migration(storage_config):
    runner = MigrationRunner(storage_config.db_path, domain="keys_db")
    try:
        runner.upgrade()
        before = _ledger_features(runner)

        removed = runner.downgrade_one()
        after = _ledger_features(runner)

        assert removed is not None
        assert removed in before
        assert removed not in after
        assert len(after) == len(before) - 1
        assert removed in runner.pending()
    finally:
        runner.close()


def test_downgrade_one_on_empty_db_returns_none(storage_config):
    runner = MigrationRunner(storage_config.db_path, domain="keys_db")
    try:
        runner.ensure_ledger()
        assert runner.downgrade_one() is None
    finally:
        runner.close()
