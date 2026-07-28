import pytest
from unittest.mock import MagicMock, AsyncMock

from muraq_kms.storage import StorageConfig, MigrationRunner, StoragePool

from muraq_kms.audit import AuditManager
from muraq_kms.keys import KeyManager
from muraq_kms.rotation import RotationManager

@pytest.fixture
def mock_storage_pool():
    pool = MagicMock()
    
    pool.async_backend.fetchall = AsyncMock()
    pool.async_backend.execute = AsyncMock()
    
    async_conn = MagicMock()
    async_cursor = MagicMock()
    async_cursor.fetchone.return_value = (90, 1700000000.0)
    async_conn.execute.return_value = async_cursor
    
    class AsyncTxContext:
        async def __aenter__(self): return async_conn
        async def __aexit__(self, exc_type, exc_val, exc_tb): pass
        
    pool.async_backend.transaction = MagicMock(return_value=AsyncTxContext())

    pool.sync_backend.fetchall = MagicMock()
    pool.sync_backend.execute = MagicMock()
    
    sync_conn = MagicMock()
    sync_cursor = MagicMock()
    sync_cursor.fetchone.return_value = (90, 1700000000.0)
    sync_conn.execute.return_value = sync_cursor
    
    class SyncTxContext:
        def __enter__(self): return sync_conn
        def __exit__(self, exc_type, exc_val, exc_tb): pass
        
    pool.sync_backend.transaction = MagicMock(return_value=SyncTxContext())
    
    return pool

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
def mock_repo():
    repo = MagicMock()
    repo.get_logical_key_by_name_async = AsyncMock(return_value=None)
    repo.create_logical_key_async = AsyncMock()
    repo.save_key_version_async = AsyncMock()
    repo.get_active_version_for_logical_key_async = AsyncMock(return_value=None)
    repo.update_key_state_async = AsyncMock()
    repo.list_keys_async = AsyncMock(return_value=[])
    
    repo.get_logical_key_by_name_sync = MagicMock(return_value=None)
    repo.create_logical_key_sync = MagicMock()
    repo.save_key_version_sync = MagicMock()
    repo.get_active_version_for_logical_key_sync = MagicMock(return_value=None)
    repo.update_key_state_sync = MagicMock()
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
    
    monkeypatch.setattr("muraq_kms.rotation.manager.encrypt_envelope", mock_encrypt)
    
    mock_spec = MagicMock()
    mock_spec.generator_func = MagicMock(return_value=b"random_raw_key_material_32bytes")
    monkeypatch.setattr("muraq_kms.rotation.manager.MuraqKMSAlgorithms.get_spec", lambda alg: mock_spec)
    
    return {
        "encrypt": mock_encrypt,
        "decrypt": mock_decrypt,
        "spec": mock_spec
    }

@pytest.fixture
def rotation_manager_instance(monkeypatch, mock_rotation_repo, mock_repo, mock_audit, valid_key_wrapping_key):
    from muraq_kms.rotation.manager import RotationManager
    
    manager = RotationManager(
        rmk=valid_key_wrapping_key,
        ask=b"audit_signing_key_32_bytes_length",
        audit_manager=mock_audit,
        pool=MagicMock(),
        key_repo=mock_repo
    )
    manager.repo = mock_rotation_repo
    return manager

@pytest.fixture
def storage_pool(tmp_path):
    """
    Creates a real StoragePool instance pointing to isolated temporary files.
    Uses MigrationRunner to automatically apply pending migrations across all domains.
    """
    config = StorageConfig(base_dir=tmp_path)
    config.ensure_layout()

    domain_mappings = [
        (config.db_path, "keys_db"),
        (config.audit_db_path, "audit_db"),
        (config.state_db_path, "state_db"),
        (config.recovery_db_path, "recovery_db"),
    ]

    for db_path, domain in domain_mappings:
        runner = MigrationRunner(db_path=db_path, domain=domain)
        runner.upgrade()
        runner.close()

    pool = StoragePool(config=config)

    yield pool

    pool.close_sync()


@pytest.fixture
def kms_integration_env(storage_pool):
    """
    Instantiates real service components bound to the storage pool.
    """
    rmk = b"0" * 32
    ask = b"1" * 32

    audit_mgr = AuditManager(pool=storage_pool)
    key_mgr = KeyManager(pool=storage_pool, audit_manager=audit_mgr, ask=ask, rmk=rmk)
    rotation_mgr = RotationManager(rmk=rmk, ask=ask, audit_manager=audit_mgr, pool=storage_pool)

    return {
        "pool": storage_pool,
        "key_mgr": key_mgr,
        "rotation_mgr": rotation_mgr,
        "audit_mgr": audit_mgr,
        "rmk": rmk,
        "ask": ask,
    }