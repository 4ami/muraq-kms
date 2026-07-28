import pytest
from unittest.mock import MagicMock, AsyncMock

@pytest.fixture
def mock_repo():
    repo = MagicMock()
    
    repo.get_logical_key_by_name_async = AsyncMock(return_value=None)
    repo.create_logical_key_async = AsyncMock()
    repo.save_key_version_async = AsyncMock()
    repo.get_active_version_for_logical_key_async = AsyncMock(return_value=None)
    repo.list_keys_async = AsyncMock(return_value=[])
    
    repo.get_logical_key_by_name_sync = MagicMock(return_value=None)
    repo.create_logical_key_sync = MagicMock()
    repo.save_key_version_sync = MagicMock()
    repo.get_active_version_for_logical_key_sync = MagicMock(return_value=None)
    repo.list_keys_sync = MagicMock(return_value=[])
    
    return repo

@pytest.fixture
def mock_audit():
    audit = MagicMock()
    audit.log_event_async = AsyncMock()
    audit.log_event_sync = MagicMock()
    return audit

@pytest.fixture
def mock_crypto(monkeypatch):
    mock_encrypt = MagicMock(return_value=b"encrypted_bytes")
    mock_decrypt = MagicMock(return_value=b"raw_unwrapped_bytes")
    
    monkeypatch.setattr("muraq_kms.keys.manager.encrypt_envelope", mock_encrypt)
    monkeypatch.setattr("muraq_kms.keys.manager.decrypt_envelope", mock_decrypt)
    
    mock_spec = MagicMock()
    mock_spec.generator_func = MagicMock(return_value=b"random_raw_key_material_32bytes")
    monkeypatch.setattr("muraq_kms.keys.manager.MuraqKMSAlgorithms.get_spec", lambda alg: mock_spec)
    
    mock_lease = MagicMock()
    mock_lease.token = "lease_token_xyz"
    
    class MockContext:
        def __enter__(self): return mock_lease
        def __exit__(self, exc_type, exc_val, exc_tb): pass
        
    monkeypatch.setattr("muraq_kms.keys.manager.borrow_key_context", lambda **kwargs: MockContext())
    
    return {
        "encrypt": mock_encrypt,
        "decrypt": mock_decrypt,
        "spec": mock_spec
    }

@pytest.fixture
def key_manager_instance(monkeypatch, mock_repo, mock_audit, valid_key_wrapping_key):
    from muraq_kms.keys.manager import KeyManager
    
    monkeypatch.setattr("muraq_kms.keys.manager.KeyRepository", lambda pool: mock_repo)
    
    manager = KeyManager(
        pool=MagicMock(), 
        audit_manager=mock_audit,
        ask=b"audit_signing_key_32_bytes_length",
        rmk=valid_key_wrapping_key
    )
    return manager

@pytest.fixture
def mock_rotation_repo():
    repo = MagicMock()
    repo.get_overdue_jobs_async = AsyncMock(return_value=[])
    repo.get_overdue_jobs_sync = MagicMock(return_value=[])
    repo.update_job_schedule_async = AsyncMock()
    repo.update_job_schedule_sync = MagicMock()
    repo.register_rotation_job_async = AsyncMock(return_value={"interval_days": 90, "next_run": 100000.0})
    repo.register_rotation_job_sync = MagicMock(return_value={"interval_days": 90, "next_run": 100000.0})
    return repo

@pytest.fixture
def rotation_manager_instance(monkeypatch, mock_repo, mock_rotation_repo, mock_audit, valid_key_wrapping_key):
    from muraq_kms.rotation.manager import RotationManager
    
    monkeypatch.setattr("muraq_kms.rotation.manager.RotationRepository", lambda pool: mock_rotation_repo)
    
    manager = RotationManager(
        rmk=valid_key_wrapping_key,
        ask=b"audit_signing_key_32_bytes_length",
        audit_manager=mock_audit,
        pool=MagicMock(),
        key_repo=mock_repo
    )
    return manager