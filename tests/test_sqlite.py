from storage.config import StorageConfig
from storage.sqlite import SQLiteStorage
from tests.helpers import insert_key_version, insert_logical_key


def test_storage_init_does_not_run_migrations(storage_config):
    storage = SQLiteStorage(storage_config)
    try:
        assert not storage_config.db_path.exists()
    finally:
        storage.close()


def test_connection_sets_pragmas(migrated_storage):
    conn = migrated_storage.connection()
    fk = conn.execute("PRAGMA foreign_keys;").fetchone()[0]
    journal = conn.execute("PRAGMA journal_mode;").fetchone()[0]

    assert fk == 1
    assert journal.lower() == "wal"


def test_get_active_kid(migrated_storage):
    logical_key_id = insert_logical_key(migrated_storage, name="active-key")
    insert_key_version(
        migrated_storage, logical_key_id, "kid-v1", version=1, state="deprecated"
    )
    insert_key_version(
        migrated_storage, logical_key_id, "kid-v2", version=2, state="active"
    )

    assert migrated_storage.get_active_kid("active-key") == "kid-v2"
    assert migrated_storage.get_active_kid("missing-key") is None


def test_list_versions_ordered(migrated_storage):
    logical_key_id = insert_logical_key(migrated_storage, name="versioned-key")
    insert_key_version(
        migrated_storage, logical_key_id, "kid-v1", version=1, state="deprecated"
    )
    insert_key_version(
        migrated_storage, logical_key_id, "kid-v2", version=2, state="active"
    )

    versions = migrated_storage.list_versions("versioned-key")

    assert len(versions) == 2
    assert versions[0][0] == "kid-v1"
    assert versions[1][0] == "kid-v2"


def test_register_dependency_and_mark_migrating(migrated_storage):
    logical_key_id = insert_logical_key(migrated_storage, name="dep-key")
    insert_key_version(migrated_storage, logical_key_id, "kid-dep", version=1)

    migrated_storage.register_dependency("dep-1", "cipher-1", "kid-dep", status="coupled")
    migrated_storage.mark_migrating("cipher-1")

    row = migrated_storage.fetchone(
        "SELECT status FROM key_dependencies WHERE _id = ?;", ("dep-1",)
    )
    assert row == ("migrating",)


def test_append_audit_entry(migrated_storage):
    migrated_storage.append_audit_entry(
        timestamp="2026-06-06T12:00:00Z",
        action="key.create",
        actor="admin",
        details='{"kid":"kid-1"}',
        status="SUCCESS",
        previous_hash="prev",
        entry_hash="hash",
    )

    row = migrated_storage.fetchone(
        "SELECT action, actor, status, hash FROM audit_log WHERE action = ?;",
        ("key.create",),
        domain="audit"
    )
    assert row == ("key.create", "admin", "SUCCESS", "hash")
