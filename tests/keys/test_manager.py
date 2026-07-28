import pytest
from unittest.mock import ANY, patch
from datetime import datetime, timezone

from muraq_kms.policies.policy_errors import PolicyDenialError

from muraq_kms.keys.key_errors import KeyLifecycleError
from muraq_kms.keys.models import KeyVersionState, KeyVersionModel

@pytest.mark.asyncio
async def test_create_key_async_success(key_manager_instance, mock_repo, mock_audit, mock_crypto):
    mock_repo.create_logical_key_async.return_value = {"_id": 101}
    
    model = await key_manager_instance.create_key_async(
        actor="admin", name="prod-encrypt-key", purpose="encryption"
    )
    
    assert isinstance(model, KeyVersionModel)
    assert model.kid == "prod-encrypt-key:v1"
    assert model.logical_key_id == 101
    assert model.state == KeyVersionState.ACTIVE
    
    mock_repo.create_logical_key_async.assert_called_once()
    mock_repo.save_key_version_async.assert_called_once()
    mock_audit.log_event_async.assert_called_once_with(
        action="kms:key_create", actor="admin", status="SUCCESS", details=ANY, ask=ANY
    )

def test_create_key_sync_conflict_throws_error(key_manager_instance, mock_repo, mock_audit):
    mock_repo.get_logical_key_by_name_sync.return_value = {"_id": 42, "name": "existing-key"}
    
    with pytest.raises(KeyLifecycleError, match="Key Identity Conflict"):
        key_manager_instance.create_key_sync(actor="user", name="existing-key", purpose="signing")
        
    mock_audit.log_event_sync.assert_called_once_with(
        action="kms:key_create", actor="user", status="FAILED", details=ANY, ask=ANY
    )

@pytest.mark.asyncio
async def test_borrow_key_async_denied_not_borrowable(key_manager_instance, mock_repo, mock_audit):
    mock_repo.get_logical_key_by_name_async.return_value = {"_id": 5, "borrowable": 0}
    
    with pytest.raises(PolicyDenialError, match="not flagged as borrowable"):
        async with key_manager_instance.borrow_key_async(actor="app-node", name="secure-key"):
            pass
            
    mock_audit.log_event_async.assert_called_once_with(
        action="kms:borrow", actor="app-node", status="DENIED", details=ANY, ask=ANY
    )

def test_borrow_key_sync_success(key_manager_instance, mock_repo, mock_audit, mock_crypto):
    mock_repo.get_logical_key_by_name_sync.return_value = {"_id": 5, "borrowable": 1, "borrow_ttl_seconds": 60}
    mock_repo.get_active_version_for_logical_key_sync.return_value = {
        "kid": "secure-key:v1", "raw_material": "aabbcc"
    }
    
    with key_manager_instance.borrow_key_sync(actor="worker-1", name="secure-key") as lease:
        assert lease is not None
        
    mock_audit.log_event_sync.assert_called_once_with(
        action="kms:borrow", actor="worker-1", status="SUCCESS", details=ANY, ask=ANY
    )

def test_get_key_version_sync_not_found(key_manager_instance, mock_repo):
    mock_repo.get_logical_key_by_name_sync.return_value = None
    result = key_manager_instance.get_key_version_sync("missing-key")
    assert result is None

def test_get_key_version_sync_success(key_manager_instance, mock_repo):
    mock_repo.get_logical_key_by_name_sync.return_value = {"_id": 99}
    mock_repo.get_active_version_for_logical_key_sync.return_value = {
        "kid": "test:v1", "logical_key_id": 99, "version": 1,
        "state": KeyVersionState.ACTIVE, "algorithm": "XChaCha20",
        "raw_material": "encrypted_string_data", "created_at": datetime.now(timezone.utc)
    }
    
    version_model = key_manager_instance.get_key_version_sync("test")
    assert isinstance(version_model, KeyVersionModel)
    assert version_model.kid == "test:v1"

@pytest.mark.asyncio
async def test_list_keys_async_has_next_lookahead(key_manager_instance, mock_repo):
    mock_repo.list_keys_async.return_value = [
        {"_id": 10, "name": "k1"},
        {"_id": 11, "name": "k2"},
        {"_id": 12, "name": "k3"},
    ]
    
    rows, next_cursor, has_next = await key_manager_instance.list_keys_async(limit=2, cursor=None)
    
    assert len(rows) == 2
    assert has_next is True
    assert next_cursor == 11

def test_list_keys_sync_no_next_page(key_manager_instance, mock_repo):
    mock_repo.list_keys_sync.return_value = [
        {"_id": 20, "name": "key-omega"}
    ]
    
    rows, next_cursor, has_next = key_manager_instance.list_keys_sync(limit=10, cursor=20)
    
    assert len(rows) == 1
    assert has_next is False
    assert next_cursor == 20

def test_export_sync_denies_unexportable_key(key_manager_instance, mock_repo, mock_audit):
    mock_repo.get_logical_key_by_name_sync.return_value = {
        "_id": "lk_123", "exportable": 0, "purpose": "encrypt"
    }

    with pytest.raises(PolicyDenialError) as exc_info:
        key_manager_instance.export_sync(name="secure_key", actor="admin")

    assert "not configured for export extraction" in str(exc_info.value)
    mock_audit.log_event_sync.assert_called_once_with(
        action="kms:export", actor="admin", status="DENIED",
        details={"logical_key": "secure_key", "reason": "Key is not flagged as exportable"},
        ask=key_manager_instance.ask
    )

def test_export_sync_fails_when_version_unreachable(key_manager_instance, mock_repo):
    mock_repo.get_logical_key_by_name_sync.return_value = {
        "_id": "lk_123", "exportable": 1, "purpose": "encrypt"
    }
    mock_repo.get_active_version_for_logical_key_sync.return_value = None

    with pytest.raises(KeyLifecycleError) as exc_info:
        key_manager_instance.export_sync(name="missing_version_key", actor="admin")

    assert "variant is unreachable" in str(exc_info.value)

@patch("muraq_kms.keys.manager.decrypt_envelope")
def test_export_sync_success_with_dependencies(mock_decrypt, key_manager_instance, mock_repo, mock_audit):
    mock_repo.get_logical_key_by_name_sync.return_value = {
        "_id": "lk_123", "exportable": 1, "purpose": "sign", "algorithm": "Ed25519", "description": "Prod Key"
    }
    mock_repo.get_active_version_for_logical_key_sync.return_value = {
        "kid": "test_key:v1", "algorithm": "Ed25519", "raw_material": "aabbcc"
    }
    mock_repo.get_dependency_count_sync.return_value = 5
    mock_decrypt.return_value = b"\x01\x02\x03"

    res = key_manager_instance.export_sync(name="test_key", actor="admin")

    assert res["key_hex"] == "010203"
    assert res["meta"]["dependencies_count"] == 5
    assert res["meta"]["description"] == "Prod Key"
    mock_audit.log_event_sync.assert_called_with(
        action="kms:export", actor="admin", status="SUCCESS",
        details={"kid": "test_key:v1"}, ask=key_manager_instance.ask
    )

@pytest.mark.asyncio
async def test_create_key_async_success_with_rotation(key_manager_instance, rotation_manager_instance, mock_repo, mock_audit, mock_crypto):
    mock_repo.create_logical_key_async.return_value = {"_id": 101}
    
    model = await key_manager_instance.create_key_async(
        actor="admin", name="prod-encrypt-key", purpose="encryption"
    )
    
    assert isinstance(model, KeyVersionModel)
    assert model.kid == "prod-encrypt-key:v1"
    
    reg_res = await rotation_manager_instance.register_rotation_job_async(model.logical_key_id, interval_days=60)
    assert reg_res["interval_days"] == 90 or reg_res["interval_days"] == 60