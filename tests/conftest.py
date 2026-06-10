import pytest
import os

from muraq_kms.storage.config import StorageConfig

@pytest.fixture
def valid_passphrase() -> str:
    return "Muraq-KMS-IS-AWeSOME-TOOL-2026!$"

@pytest.fixture
def valid_salt() -> bytes:
    return os.urandom(16)

@pytest.fixture
def valid_deployment_salt() -> bytes:
    return os.urandom(32)

@pytest.fixture
def valid_drs() -> bytes:
    return os.urandom(32)

@pytest.fixture
def valid_key_wrapping_key() -> bytes:
    return os.urandom(32)

@pytest.fixture
def storage_config(tmp_path) -> StorageConfig:
    return StorageConfig(tmp_path / "kms_test_vault")

@pytest.fixture(autouse=True)
def clean_env_isolation(monkeypatch):
    monkeypatch.delenv("MKMS_DATA_DIR", raising=False)