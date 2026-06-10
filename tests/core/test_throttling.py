import sqlite3
from muraq_kms.core.throttling import ThrottlingEngine

def test_throttler_initial_status_with_seed_signature(initialized_core_context):
    throttler = ThrottlingEngine(initialized_core_context, "test-deployment-id-uuid-4444")
    
    status = throttler.check_status()
    assert status.was_tampered is False
    assert status.is_locked is False
    assert status.remaining_attempts == 5

    with sqlite3.connect(initialized_core_context.state_db_path) as conn:
        sig = conn.execute("SELECT tamper_signature FROM throttling_state WHERE id=1").fetchone()[0]
        assert sig != "INITIALIZED"

def test_throttler_failure_velocity_lockout_trigger(initialized_core_context):
    throttler = ThrottlingEngine(initialized_core_context, "test-deployment-id-uuid-4444")
    
    for i in range(4):
        status = throttler.record_failure()
        assert status.is_locked is False
        assert status.remaining_attempts == (4 - i)
        
    lockout_status = throttler.record_failure()
    assert lockout_status.is_locked is True
    assert lockout_status.remaining_attempts == 0
    assert lockout_status.remaining_seconds <= 600

def test_throttler_detects_arbitrary_sqlite_row_tampering(initialized_core_context):
    throttler = ThrottlingEngine(initialized_core_context, "test-deployment-id-uuid-4444")
    throttler.check_status()
    
    with sqlite3.connect(initialized_core_context.state_db_path) as conn:
        conn.execute("UPDATE throttling_state SET failed_attempts = 1 WHERE id = 1")
        conn.commit()
        
    status = throttler.check_status()
    assert status.was_tampered is True
    assert status.is_locked is True

def test_throttler_self_heals_missing_file_as_tamper_event(initialized_core_context):
    throttler = ThrottlingEngine(initialized_core_context, "test-deployment-id-uuid-4444")
    throttler.check_status()
    
    initialized_core_context.state_db_path.unlink()
    
    status = throttler.check_status()
    assert status.was_tampered is True
    assert status.is_locked is True
    assert status.remaining_seconds == throttler.TAMPER_LOCKOUT_DURATION