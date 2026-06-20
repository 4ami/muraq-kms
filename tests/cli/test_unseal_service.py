from unittest.mock import patch, MagicMock
from muraq_kms.cli.services.unseal_service import unseal_kms
from muraq_kms.core.engine import EngineError



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
    assert "CRITICAL" in captured
    assert "Manifest identity forgery detected" in captured

@patch("muraq_kms.cli.shells.unsealed_shell.key_services.handle_export")
def test_shell_key_export_routes_arguments_correctly(mock_handle_export, test_unsealed_shell):
    test_unsealed_shell.do_key("-export my_crypto_key -f env:APP_SECRET -o /tmp/.env")

    mock_handle_export.assert_called_once()
    called_manager, called_actor, called_args = mock_handle_export.call_args[0]
    
    assert called_manager == test_unsealed_shell.key_manager
    assert called_actor == "operator-dev"
    assert called_args.name == "my_crypto_key"
    assert called_args.format == "env:APP_SECRET"
    assert called_args.output == "/tmp/.env"

@patch("muraq_kms.cli.shells.unsealed_shell.key_services.handle_export")
def test_shell_key_export_falls_back_to_defaults(mock_handle_export, test_unsealed_shell):
    test_unsealed_shell.do_key("-export default_key")

    mock_handle_export.assert_called_once()
    _, _, called_args = mock_handle_export.call_args[0]
    
    assert called_args.name == "default_key"
    assert called_args.format == "json"
    assert called_args.output is None