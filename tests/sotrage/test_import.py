def test_import_storage_has_no_side_effects(storage_config, monkeypatch):
    monkeypatch.setenv("MKMS_DATA_DIR", str(storage_config.base_dir))

    import muraq_kms.storage

    assert not storage_config.db_path.exists()
    assert muraq_kms.storage.__all__ == ["StorageConfig", "MigrationRunner", "SQLiteStorage"]
