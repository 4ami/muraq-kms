from pathlib import Path

from muraq_kms.storage.config import StorageConfig


def test_db_path_under_base_dir(storage_config):
    assert storage_config.db_path == storage_config.base_dir / "keys.db"


def test_from_env_uses_mkms_data_dir(monkeypatch, tmp_path):
    data_dir = tmp_path / "custom-kms"
    monkeypatch.setenv("MKMS_DATA_DIR", str(data_dir))

    config = StorageConfig.from_env()

    assert config.base_dir == (data_dir / ".muraq-kms")


def test_from_env_default_path(monkeypatch):
    monkeypatch.delenv("MKMS_DATA_DIR", raising=False)

    config = StorageConfig.from_env()

    assert config.base_dir == (Path.home() / ".muraq-kms").resolve()


def test_ensure_layout_creates_directories(storage_config):
    storage_config.ensure_layout()

    assert storage_config.base_dir.is_dir()
    for subdir in ("audit", "recovery", "backups"):
        assert (storage_config.base_dir / subdir).is_dir()
