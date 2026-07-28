import asyncio
from datetime import datetime, timezone, timedelta
import pytest

from muraq_kms.storage.pool import StoragePool
from muraq_kms.policies.models import KeyAccessPolicy
from muraq_kms.keys.models import KeyVersionState
from muraq_kms.audit.manager import AuditManager
from muraq_kms.keys.manager import KeyManager
from muraq_kms.rotation.manager import RotationManager
from muraq_kms.rotation.scheduler import RotationScheduler

@pytest.mark.asyncio
async def test_async_key_lifecycle_and_rotation_integration(kms_integration_env):
    """
    Tests full async flow:
    Key creation -> Rotation registration -> Schedule trigger -> Active/Deprecated key material check.
    """
    key_mgr: KeyManager = kms_integration_env["key_mgr"]
    rotation_mgr: RotationManager = kms_integration_env["rotation_mgr"]
    audit_mgr: AuditManager = kms_integration_env["audit_mgr"]
    pool: StoragePool = kms_integration_env["pool"]
    ask: bytes = kms_integration_env["ask"]

    key_name = "db-encryption-key"
    actor = "admin_user"

    policy = KeyAccessPolicy(export=True, borrow=True, borrow_ttl_seconds=60)
    v1_model = await key_mgr.create_key_async(
        actor=actor,
        name=key_name,
        purpose="encryption",
        algorithm="XChaCha20",
        policy=policy
    )

    assert v1_model.kid == f"{key_name}:v1"
    assert v1_model.version == 1
    assert v1_model.state == KeyVersionState.ACTIVE

    v1_export = await key_mgr.export_async(name=key_name, actor=actor)
    v1_raw_hex = v1_export["key_hex"]

    logical_key = await key_mgr.repo.get_logical_key_by_name_async(key_name)
    job_info = await rotation_mgr.register_rotation_job_async(
        logical_key_id=logical_key["_id"],
        interval_days=30
    )
    assert job_info["interval_days"] == 30

    overdue_ts = (datetime.now(tz=timezone.utc) - timedelta(days=1)).timestamp()
    await pool.async_backend.execute(
        "UPDATE rotation_jobs SET next_run = ? WHERE logical_key_id = ?;",
        (overdue_ts, logical_key["_id"]),
        domain="keys"
    )

    await rotation_mgr.process_scheduled_rotations()

    v2_active = await key_mgr.get_key_version_async(key_name)
    assert v2_active.kid == f"{key_name}:v2"
    assert v2_active.version == 2
    assert v2_active.state == KeyVersionState.ACTIVE

    v2_export = await key_mgr.export_async(name=key_name, actor=actor)
    v2_raw_hex = v2_export["key_hex"]

    assert v1_raw_hex != v2_raw_hex

    v1_historical = await key_mgr.repo.get_key_version_by_kid_async(kid=f"{key_name}:v1")
    assert v1_historical["state"] == KeyVersionState.DEPRECATED.value
    is_intact, _ = await audit_mgr.verify_chain_integrity_async(ask=ask)
    assert is_intact is True

def test_sync_key_lifecycle_and_rotation_integration(kms_integration_env):
    """
    Tests full synchronous flow through real storage engines and migrated files.
    """
    key_mgr: KeyManager = kms_integration_env["key_mgr"]
    rotation_mgr: RotationManager = kms_integration_env["rotation_mgr"]
    audit_mgr: AuditManager = kms_integration_env["audit_mgr"]
    pool: StoragePool = kms_integration_env["pool"]
    ask: bytes = kms_integration_env["ask"]

    key_name = "payment-signing-key"
    actor = "system_operator"

    policy = KeyAccessPolicy(export=True)
    v1_model = key_mgr.create_key_sync(
        actor=actor,
        name=key_name,
        purpose="signing",
        algorithm="AES256",
        policy=policy
    )
    assert v1_model.kid == f"{key_name}:v1"

    v1_raw_hex = key_mgr.export_sync(name=key_name, actor=actor)["key_hex"]

    logical_key = key_mgr.repo.get_logical_key_by_name_sync(key_name)
    rotation_mgr.register_rotation_job_sync(logical_key_id=logical_key["_id"], interval_days=90)

    past_ts = (datetime.now(tz=timezone.utc) - timedelta(hours=2)).timestamp()
    pool.sync_backend.execute(
        "UPDATE rotation_jobs SET next_run = ? WHERE logical_key_id = ?;",
        (past_ts, logical_key["_id"]),
        domain="keys"
    )

    rotated_kids = rotation_mgr.evaluate_and_rotate()
    assert rotated_kids == [f"{key_name}:v2"]

    v2_raw_hex = key_mgr.export_sync(name=key_name, actor=actor)["key_hex"]
    assert v1_raw_hex != v2_raw_hex

    v1_historical = key_mgr.repo.get_key_version_by_kid_sync(kid=f"{key_name}:v1")
    assert v1_historical["state"] == KeyVersionState.DEPRECATED.value

    is_intact, _ = audit_mgr.verify_chain_integrity_sync(ask=ask)
    assert is_intact is True

@pytest.mark.asyncio
async def test_rotation_scheduler_background_task_integration(kms_integration_env):
    """
    Tests real background daemon scheduling and rotation against disk storage.
    """
    key_mgr: KeyManager = kms_integration_env["key_mgr"]
    rotation_mgr: RotationManager = kms_integration_env["rotation_mgr"]
    pool: StoragePool = kms_integration_env["pool"]

    key_name = "session-wrapping-key"
    actor = "auth_service"

    await key_mgr.create_key_async(
        actor=actor,
        name=key_name,
        purpose="wrapping",
        algorithm="AES256",
        policy=KeyAccessPolicy(export=True)
    )

    v1_raw_hex = (await key_mgr.export_async(name=key_name, actor=actor))["key_hex"]

    logical_key = await key_mgr.repo.get_logical_key_by_name_async(key_name)
    await rotation_mgr.register_rotation_job_async(logical_key_id=logical_key["_id"], interval_days=1)

    past_ts = (datetime.now(tz=timezone.utc) - timedelta(seconds=10)).timestamp()
    await pool.async_backend.execute(
        "UPDATE rotation_jobs SET next_run = ? WHERE logical_key_id = ?;",
        (past_ts, logical_key["_id"]),
        domain="keys"
    )

    scheduler = RotationScheduler(manager=rotation_mgr)
    scheduler.start(interval_seconds=1)

    await asyncio.sleep(0.5)
    await scheduler.stop()

    v2_active = await key_mgr.get_key_version_async(key_name)
    assert v2_active.kid == f"{key_name}:v2"

    v2_raw_hex = (await key_mgr.export_async(name=key_name, actor=actor))["key_hex"]
    assert v1_raw_hex != v2_raw_hex