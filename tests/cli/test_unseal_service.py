import pytest
from unittest.mock import patch, MagicMock
from muraq_kms.cli.services.unseal_service import unseal_kms
from muraq_kms.core.engine import CoreEngine, EngineError



@patch("muraq_kms.cli.services.unseal_service.getpass")
@patch("muraq_kms.cli.services.unseal_service.get_deployment_id", return_value="test-id")
@patch("muraq_kms.cli.services.unseal_service.ThrottlingEngine")
def test_unseal_loop_checks_lockout_dynamically_per_iteration(
    mock_throttler_cls, mock_get_id, mock_getpass, prepared_engine, capsys
):
    mock_throttler = MagicMock()
    mock_throttler_cls.return_value = mock_throttler

    status_allowed = MagicMock(is_locked=False, was_tampered=False, remaining_attempts=1)
    status_locked = MagicMock(is_locked=True, was_tampered=False, remaining_attempts=0)
    
    mock_throttler.check_status.side_effect = [status_allowed, status_allowed, status_locked]
    mock_getpass.return_value = "typo-passphrase"
    
    prepared_engine.unseal = MagicMock(side_effect=EngineError("Invalid passphrase"))
    mock_throttler.record_failure.return_value = status_locked

    unseal_kms(prepared_engine)

    captured = capsys.readouterr().out
    
    assert "Critical: Maximum execution attempts reached" in captured
    assert "Access Denied. Engine locked" in captured
    assert mock_getpass.call_count == 1


@patch("muraq_kms.cli.services.unseal_service.getpass")
@patch("muraq_kms.cli.services.unseal_service.get_deployment_id", return_value="test-id")
@patch("muraq_kms.cli.services.unseal_service.ThrottlingEngine")
def test_unseal_intercepts_critical_exception_and_slams_door(
    mock_throttler_cls, mock_get_id, mock_getpass, prepared_engine, capsys
):
    mock_throttler = MagicMock()
    mock_throttler_cls.return_value = mock_throttler
    
    mock_throttler.check_status.return_value = MagicMock(is_locked=False, was_tampered=False, remaining_attempts=5)
    mock_getpass.return_value = "valid-pass-but-spoofed-metadata"

    prepared_engine.unseal = MagicMock(side_effect=EngineError("CRITICAL: Manifest identity forgery detected."))

    unseal_kms(prepared_engine)

    mock_throttler.enforce_tamper_lockout.assert_called_once()
    captured = capsys.readouterr().out
    assert "🚨 CRITICAL:" in captured