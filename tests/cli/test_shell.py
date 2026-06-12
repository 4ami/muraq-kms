from unittest.mock import patch, MagicMock

from muraq_kms.core.engine import EngineState, EngineError

import json

def test_shell_prompt_lifecycle_transitions(test_cli_shell):
    assert "SEALED" in test_cli_shell.prompt
    
    test_cli_shell.engine._state = EngineState.UNSEALED
    test_cli_shell.postcmd(stop=False, line="")
    assert "UNSEALED" in test_cli_shell.prompt

@patch("muraq_kms.cli.services.init_service.getpass")
@patch("muraq_kms.cli.services.init_service.bootstrap")
@patch("muraq_kms.cli.services.init_service.preflight_testing", return_value=True)
def test_init_loop_handles_weak_passphrase_retry(mock_preflight, mock_bootstrap, mock_getpass, test_cli_shell):
    mock_getpass.side_effect = [
        "weak", 
        "ValidPass123!", "Mismatch123!", 
        "ValidPass123!", "ValidPass123!"
    ]
    
    test_cli_shell.onecmd("init")
    
    assert mock_bootstrap.called is True

@patch("muraq_kms.cli.services.unseal_service.getpass")
def test_unseal_intercepts_tamper_lockout_before_password_prompt(mock_getpass, test_cli_shell, capsys):
    test_cli_shell.config.ensure_layout()
    base_dir = test_cli_shell.config.base_dir

    manifest_data = {
        "deployment_id": "spoofed-attacker-uuid",
        "kdf_salt_hex": "a1b2c3d4",
        "deployment_salt_hex": "e5f6a7b8"
    }

    with open(base_dir / "manifest.json", "w", encoding="utf-8") as m:
        json.dump(manifest_data, m)
    with open(base_dir / "drs.enc", "wb") as d:
        d.write(b"encrypted-bytes-stream")
    with open(base_dir / "signature.enc", "wb") as s:
        s.write(b"encrypted-signature-metadata-mock")

    test_cli_shell.onecmd("unseal")
    
    captured = capsys.readouterr().out
    assert "SECURITY ALTERCATION" in captured
    assert "DETECTED" in captured
    assert "Engine state anomalies" in captured
    assert "validation failure" in captured
    assert "Access temporarily throttled for 30 minutes" in captured
    assert mock_getpass.called is False, "Security failure: Prompted for a password during an active tamper event."

@patch("muraq_kms.cli.services.unseal_service.getpass")
@patch("muraq_kms.cli.services.unseal_service.ThrottlingEngine")
def test_cli_unseal_intercepts_identity_forgery_heals_manifest_and_locks_down(
    mock_throttler_cls, mock_getpass, test_cli_shell, capsys
):
    """
    Ensures that when CoreEngine raises a critical identity spoofing error during unseal,
    the CLI layer intercepts it, triggers a full system tamper lockdown on the true ID,
    and reports the recovery sequence to stdout.
    """
    test_cli_shell.config.ensure_layout()
    base_dir = test_cli_shell.config.base_dir
    
    with open(base_dir / "manifest.json", "w", encoding="utf-8") as m:
        json.dump({"deployment_id": "spoofed-attacker-uuid", "kdf_salt_hex": "00", "deployment_salt_hex": "00"}, m)
    (base_dir / "drs.enc").touch()
    (base_dir / "signature.enc").touch()

    mock_throttler = MagicMock()
    mock_throttler.check_status.return_value = MagicMock(is_locked=False, was_tampered=False, remaining_attempts=5)
    mock_throttler_cls.return_value = mock_throttler

    mock_getpass.return_value = "CorrectMasterPassphrase123!"
    
    def mock_unseal_behavior(*args, **kwargs):
        with open(base_dir / "manifest.json", "w", encoding="utf-8") as m:
            json.dump({"deployment_id": "legitimate-production-uuid", "kdf_salt_hex": "00", "deployment_salt_hex": "00"}, m)
        raise EngineError("CRITICAL: Manifest identity forgery detected. System recovered and locked.")

    test_cli_shell.engine.unseal = MagicMock(side_effect=mock_unseal_behavior)

    test_cli_shell.onecmd("unseal")

    captured = capsys.readouterr().out
    assert "CRITICAL" in captured or "identity forgery" in captured.lower()
    
    mock_throttler.enforce_tamper_lockout.assert_called_once()
    
    with open(base_dir / "manifest.json", "r", encoding="utf-8") as m:
        disk_data = json.load(m)
    assert disk_data["deployment_id"] == "legitimate-production-uuid"

@patch("muraq_kms.core.doctor.doctor.DoctorEngine._verify_sqlite", return_value=True)
@patch("muraq_kms.core.doctor.doctor.ThrottlingEngine")
def test_cli_fix_command_refuses_execution_during_active_tamper(
    mock_throttler_cls, mock_verify_sqlite, test_cli_shell, capsys
):
    """
    Verifies that the administrative 'fix' command drops dead immediately if DoctorEngine
    flags a critical validation tamper footprint, preventing lockout state purging exploits.
    """
    test_cli_shell.config.ensure_layout()
    base_dir = test_cli_shell.config.base_dir

    with open(base_dir / "manifest.json", "w") as m:
        json.dump({"deployment_id": "prod-uuid", "kdf_salt_hex": "00", "deployment_salt_hex": "00"}, m)
    (base_dir / "signature.enc").touch()
    (base_dir / "state.db").touch()

    mock_status = MagicMock()
    mock_status.was_tampered = True
    mock_status.is_locked = True

    mock_throttler = MagicMock()
    mock_throttler.check_status.return_value = mock_status
    mock_throttler_cls.return_value = mock_throttler

    test_cli_shell.onecmd("fix")

    captured = capsys.readouterr().out
    assert "CRITICAL REFUSAL" in captured or "integrity violation" in captured.lower()
    assert "Auto-repair disabled" in captured

def test_cli_unseal_blocks_cleanly_when_validation_anchor_is_omitted(test_cli_shell, capsys):
    """
    Verifies that if signature.enc is entirely missing, the unseal service stops execution
    cleanly with a warning description instead of throwing an unhandled FileNotFoundError trace dump.
    """
    test_cli_shell.config.ensure_layout()
    base_dir = test_cli_shell.config.base_dir

    with open(base_dir / "manifest.json", "w") as m:
        json.dump({"deployment_id": "prod-uuid", "kdf_salt_hex": "00", "deployment_salt_hex": "00"}, m)
    (base_dir / "drs.enc").touch()
    
    if (base_dir / "signature.enc").exists():
        (base_dir / "signature.enc").unlink()

    test_cli_shell.onecmd("unseal")

    captured = capsys.readouterr().out
    assert "Unseal Blocked" in captured or "missing initialization components" in captured.lower()

def test_cli_fix_command_aborts_on_uninitialized_system(test_cli_shell, capsys):
    """
    Verifies that executing 'fix' on a clean environment drops execution immediately
    without trying to migrate database infrastructure.
    """
    test_cli_shell.config.ensure_layout()
    
    manifest_path = test_cli_shell.config.base_dir / "manifest.json"
    if manifest_path.exists():
        manifest_path.unlink()

    test_cli_shell.onecmd("fix")
    
    captured = capsys.readouterr().out
    assert "System has not been initialized yet" in captured
    assert "Please run the" in captured
    assert "init" in captured
    assert "command first to deploy your KMS instance safely" in captured

@patch("muraq_kms.cli.services.unseal_service.getpass")
@patch("muraq_kms.cli.services.unseal_service.ThrottlingEngine")
def test_cli_unseal_intercepts_identity_forgery_heals_manifest_and_locks_down(
    mock_throttler_cls, mock_getpass, test_cli_shell, capsys
):
    """
    Ensures that when CoreEngine raises an identity spoofing alert during unseal,
    the CLI layer catches it, applies a penalty to the true ID, and writes recovery flags.
    """
    test_cli_shell.config.ensure_layout()
    base_dir = test_cli_shell.config.base_dir
    
    with open(base_dir / "manifest.json", "w", encoding="utf-8") as m:
        json.dump({"deployment_id": "spoofed-attacker-uuid", "kdf_salt_hex": "00", "deployment_salt_hex": "00"}, m)
    (base_dir / "drs.enc").touch()
    (base_dir / "signature.enc").touch()

    mock_throttler = MagicMock()
    mock_throttler.check_status.return_value = MagicMock(is_locked=False, was_tampered=False, remaining_attempts=5)
    mock_throttler_cls.return_value = mock_throttler
    mock_getpass.return_value = "CorrectMasterPassphrase123!"
    
    def mock_unseal_behavior(*args, **kwargs):
        with open(base_dir / "manifest.json", "w", encoding="utf-8") as m:
            json.dump({"deployment_id": "legitimate-production-uuid", "kdf_salt_hex": "00", "deployment_salt_hex": "00"}, m)
        raise EngineError("CRITICAL: Manifest identity forgery detected. System recovered and locked.")

    test_cli_shell.engine.unseal = MagicMock(side_effect=mock_unseal_behavior)

    test_cli_shell.onecmd("unseal")

    captured = capsys.readouterr().out
    assert "identity forgery" in captured.lower()
    mock_throttler.enforce_tamper_lockout.assert_called_once()
    
    with open(base_dir / "manifest.json", "r", encoding="utf-8") as m:
        disk_data = json.load(m)
    assert disk_data["deployment_id"] == "legitimate-production-uuid"

@patch("muraq_kms.core.doctor.doctor.DoctorEngine._verify_sqlite", return_value=True)
@patch("muraq_kms.core.doctor.doctor.ThrottlingEngine")
def test_cli_fix_command_refuses_execution_during_active_tamper(
    mock_throttler_cls, mock_verify_sqlite, test_cli_shell, capsys
):
    """
    Verifies that the administrative 'fix' command refuses execution if DoctorEngine
    flags a critical validation tamper footprint.
    """
    test_cli_shell.config.ensure_layout()
    base_dir = test_cli_shell.config.base_dir

    with open(base_dir / "manifest.json", "w") as m:
        json.dump({"deployment_id": "prod-uuid", "kdf_salt_hex": "00", "deployment_salt_hex": "00"}, m)
    (base_dir / "signature.enc").touch()
    (base_dir / "state.db").touch()

    mock_status = MagicMock()
    mock_status.was_tampered = True 
    mock_status.is_locked = True

    mock_throttler = MagicMock()
    mock_throttler.check_status.return_value = mock_status
    mock_throttler_cls.return_value = mock_throttler

    test_cli_shell.onecmd("fix")

    captured = capsys.readouterr().out
    assert "integrity violation" in captured.lower() or "critical refusal" in captured.lower()
    assert "Auto-repair disabled" in captured