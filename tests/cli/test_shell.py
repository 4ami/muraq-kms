from unittest.mock import patch
from muraq_kms.core.engine import EngineState

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
    with open(test_cli_shell.config.base_dir / "manifest.json", "w") as m:
        m.write('{"deployment_id": "cli-test-uuid", "kdf_salt_hex": "00", "deployment_salt_hex": "00"}')
    with open(test_cli_shell.config.base_dir / "drs.enc", "w") as d:
        d.write("encrypted-bytes-stream")
        
    if test_cli_shell.config.state_db_path.exists():
        test_cli_shell.config.state_db_path.unlink()
        

    test_cli_shell.onecmd("unseal")
    
    captured = capsys.readouterr().out
    assert "SECURITY WARNING" in captured
    assert "Access temporarily throttled for 30 minutes" in captured
    assert mock_getpass.called is False, "Security failure: Prompted for a password during an active tamper event."