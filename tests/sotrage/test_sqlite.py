from muraq_kms.storage.sqlite import SQLiteStorage
from tests.sotrage.helpers import insert_key_version, insert_logical_key


def test_sqlite_storage_domain_mapping_isolation(migrated_storage):
    keys_conn = migrated_storage.connection(domain="keys")
    state_conn = migrated_storage.connection(domain="state")
    
    assert migrated_storage._config.db_path.exists()
    assert migrated_storage._config.state_db_path.exists()
    assert keys_conn != state_conn

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

    sql = """
    SELECT kv.kid
    FROM key_versions kv
    JOIN logical_keys lk ON lk._id = kv.logical_key_id
    WHERE lk.name = ? AND kv.state = 'active'
    LIMIT 1;
    """
    cursor = migrated_storage.execute(sql, ("active-key",), domain="keys")
    assert cursor.fetchone()[0] == "kid-v2"
    cursor = migrated_storage.execute(sql, ("missing-key",), domain="keys")
    assert cursor.fetchone() is None


def test_list_versions_ordered(migrated_storage):
    logical_key_id = insert_logical_key(migrated_storage, name="versioned-key")
    insert_key_version(
        migrated_storage, logical_key_id, "kid-v1", version=1, state="deprecated"
    )
    insert_key_version(
        migrated_storage, logical_key_id, "kid-v2", version=2, state="active"
    )

    sql = """
    SELECT kv.kid, kv.version, kv.state, kv.algorithm, kv.created_at
    FROM key_versions kv
    JOIN logical_keys lk ON lk._id = kv.logical_key_id
    WHERE lk.name = ?
    ORDER BY kv.version;
    """
    
    versions = migrated_storage.fetchall(sql, ("versioned-key",), domain='keys')

    assert len(versions) == 2
    assert versions[0][0] == "kid-v1"
    assert versions[1][0] == "kid-v2"


def test_register_dependency_and_mark_migrating(migrated_storage):
    logical_key_id = insert_logical_key(migrated_storage, name="dep-key")
    insert_key_version(migrated_storage, logical_key_id, "kid-dep", version=1)
    sql = """
    INSERT INTO key_dependencies (_id, ciphertext_id, ref_kid, status)
    VALUES (?, ?, ?, ?);
    """
    migrated_storage.execute(sql, ("dep-1", "cipher-1", "kid-dep", "coupled"))
    sql = """
    UPDATE key_dependencies
    SET status = 'migrating'
    WHERE ciphertext_id = ?;
    """
    migrated_storage.execute(sql, ("cipher-1",))

    row = migrated_storage.fetchone(
        "SELECT status FROM key_dependencies WHERE _id = ?;", ("dep-1",)
    )
    assert row == ("migrating",)

