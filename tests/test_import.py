from pathlib import Path


def test_import_storage_has_no_side_effects(storage_config, monkeypatch):
    monkeypatch.setenv("MKMS_DATA_DIR", str(storage_config.base_dir))

    import storage  # noqa: F401

    assert not storage_config.db_path.exists()
    assert storage.__all__ == ["StorageConfig", "MigrationRunner", "SQLiteStorage"]
