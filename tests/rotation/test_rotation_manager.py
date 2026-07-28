import pytest
from unittest.mock import MagicMock
from muraq_kms.keys.models import KeyVersionState
from muraq_kms.rotation.manager import RotationManager

@pytest.mark.asyncio
async def test_manager_uninitialized_repository_raises():
    manager = RotationManager(rmk=b"0"*32, ask=b"1"*32, audit_manager=MagicMock(), pool=None)
    
    with pytest.raises(RuntimeError, match="without a valid StoragePool or RotationRepository"):
        await manager.register_rotation_job_async(1)
        
    with pytest.raises(RuntimeError, match="without a valid StoragePool or RotationRepository"):
        manager.register_rotation_job_sync(1)

    with pytest.raises(RuntimeError, match="without a valid StoragePool or KeyRepository"):
        manager.evaluate_and_rotate()

@pytest.mark.asyncio
async def test_process_scheduled_rotations_async_success(rotation_manager_instance, mock_rotation_repo, mock_repo, mock_audit, mock_crypto):
    mock_rotation_repo.get_overdue_jobs_async.return_value = [
        {"job_id": 1, "logical_key_id": 10, "interval_days": 30, "key_name": "master-key"}
    ]
    mock_repo.get_active_version_for_logical_key_async.return_value = {
        "kid": "master-key:v1",
        "version": 1,
        "algorithm": "AES256"
    }

    await rotation_manager_instance.process_scheduled_rotations()

    mock_repo.update_key_state_async.assert_called_once_with(
        kid="master-key:v1",
        next_state=KeyVersionState.DEPRECATED
    )

    mock_repo.save_key_version_async.assert_called_once()
    saved_model = mock_repo.save_key_version_async.call_args[0][0]
    assert saved_model.kid == "master-key:v2"
    assert saved_model.version == 2

    mock_rotation_repo.update_job_schedule_async.assert_called_once()
    
    mock_audit.log_event_async.assert_called_once_with(
        action="KEY_ROTATE",
        actor="system:rotation_daemon",
        details={
            "logical_key_id": 10,
            "old_kid": "master-key:v1",
            "new_kid": "master-key:v2",
            "algorithm": "AES256"
        },
        status="SUCCESS",
        ask=rotation_manager_instance.ask,
        timestamp=pytest.any if hasattr(pytest, 'any') else saved_model.created_at
    )

@pytest.mark.asyncio
async def test_process_scheduled_rotations_fail_closed_on_missing_active_version(rotation_manager_instance, mock_rotation_repo, mock_repo, mock_audit):
    mock_rotation_repo.get_overdue_jobs_async.return_value = [
        {"job_id": 2, "logical_key_id": 99, "interval_days": 30, "key_name": "broken-key"}
    ]
    mock_repo.get_active_version_for_logical_key_async.return_value = None

    await rotation_manager_instance.process_scheduled_rotations()

    mock_audit.log_event_async.assert_called_once_with(
        action="KEY_ROTATE",
        actor="system:rotation_daemon",
        details={"key_name": "broken-key", "error": "Cannot rotate key 'broken-key': No active version found."},
        status="FAILED",
        ask=rotation_manager_instance.ask
    )

def test_evaluate_and_rotate_sync_success(rotation_manager_instance, mock_rotation_repo, mock_repo, mock_audit, mock_crypto):
    mock_rotation_repo.get_overdue_jobs_sync.return_value = [
        {"job_id": 3, "logical_key_id": 20, "interval_days": 90, "key_name": "cli-key"}
    ]
    mock_repo.get_active_version_for_logical_key_sync.return_value = {
        "kid": "cli-key:v3",
        "version": 3,
        "algorithm": "XCHACHA20"
    }

    rotated_kids = rotation_manager_instance.evaluate_and_rotate()

    assert rotated_kids == ["cli-key:v4"]
    mock_repo.update_key_state_sync.assert_called_once_with(
        kid="cli-key:v3",
        next_state=KeyVersionState.DEPRECATED
    )
    mock_repo.save_key_version_sync.assert_called_once()
    mock_audit.log_event_sync.assert_called_once()

def test_evaluate_and_rotate_sync_exception_continues_loop(rotation_manager_instance, mock_rotation_repo, mock_repo, mock_audit):
    mock_rotation_repo.get_overdue_jobs_sync.return_value = [
        {"job_id": 1, "logical_key_id": 1, "interval_days": 10, "key_name": "bad-key"},
        {"job_id": 2, "logical_key_id": 2, "interval_days": 10, "key_name": "good-key"}
    ]
    
    mock_repo.get_active_version_for_logical_key_sync.side_effect = [
        None,
        {"kid": "good-key:v1", "version": 1, "algorithm": "XChaCha20"}
    ]

    rotated_kids = rotation_manager_instance.evaluate_and_rotate()

    assert rotated_kids == ["good-key:v2"]
    mock_audit.log_event_sync.assert_any_call(
        action="KEY_ROTATE",
        actor="cli:rotation_worker",
        details={"key_name": "bad-key", "error": "Cannot rotate key 'bad-key': No active version found."},
        status="FAILED",
        ask=rotation_manager_instance.ask
    )