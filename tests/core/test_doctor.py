from unittest.mock import MagicMock, patch

from muraq_kms.storage.config import StorageConfig
from muraq_kms.core.doctor.doctor import DoctorEngine
from muraq_kms.core.doctor.data_classes import DiagnosticReport, Issue

from helpers import create_corrupt_file, create_valid_sqlite

import json 

def test_diagnose_manifest_missing_and_corrupt(tmp_path):
    issues = DoctorEngine._diagnose_manifest(tmp_path)
    assert len(issues) == 1
    assert issues[0].asset == "manifest.json"
    assert issues[0].is_critical is True
    assert issues[0].can_fix is False

    create_corrupt_file(tmp_path / "manifest.json")
    issues = DoctorEngine._diagnose_manifest(tmp_path)
    assert len(issues) == 1
    assert "malformed/corrupted" in issues[0].message
    assert issues[0].is_critical is True

def test_diagnose_manifest_healthy(tmp_path):
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps({"deployment_id": "test-123"}), encoding="utf-8")
    
    issues = DoctorEngine._diagnose_manifest(tmp_path)
    assert len(issues) == 0

def test_diagnose_drs_states(tmp_path):
    issue = DoctorEngine._diagnose_drs(tmp_path)
    assert issue is not None
    assert issue.asset == "drs.enc"
    assert issue.is_critical is True

    (tmp_path / "drs.enc").write_bytes(b"encrypted_key_stream")
    issue = DoctorEngine._diagnose_drs(tmp_path)
    assert issue is None

def test_diagnose_keys_db_missing_and_corrupt(tmp_path):
    db_path = tmp_path / "keys.db"

    issues = DoctorEngine._diagnose_keysdb(db_path)
    assert len(issues) == 1
    assert issues[0].is_critical is True
    assert issues[0].can_fix is False

    create_corrupt_file(db_path)
    issues = DoctorEngine._diagnose_keysdb(db_path)
    assert len(issues) == 1
    assert "corruption detected" in issues[0].message

def test_diagnose_auxiliary_dbs_missing_and_corrupt(tmp_path):
    audit_path = tmp_path / "audit.db"
    recovery_path = tmp_path / "recovery.db"

    audit_issues = DoctorEngine._diagnose_auditdb(audit_path)
    recovery_issues = DoctorEngine._diagnose_recoverydb(recovery_path)
    
    assert audit_issues[0].is_critical is False
    assert audit_issues[0].can_fix is True
    assert recovery_issues[0].is_critical is False
    assert recovery_issues[0].can_fix is True

    create_corrupt_file(audit_path)
    create_corrupt_file(recovery_path)

    assert len(DoctorEngine._diagnose_auditdb(audit_path)) == 1
    assert len(DoctorEngine._diagnose_recoverydb(recovery_path)) == 1

def test_diagnose_statedb_missing_and_corrupt(tmp_path):
    config_mock = MagicMock(spec=StorageConfig)
    state_path = tmp_path / "state.db"

    issues = DoctorEngine._diagnose_statedb(config_mock, state_path, "dep-id")
    assert issues[0].asset == "state.db"
    assert issues[0].can_fix is True

    create_corrupt_file(state_path)
    issues = DoctorEngine._diagnose_statedb(config_mock, state_path, "dep-id")
    assert "structurally corrupted" in issues[0].message

@patch("muraq_kms.core.doctor.doctor.ThrottlingEngine")
def test_diagnose_statedb_tamper_detection(mock_throttler_class, tmp_path):
    config_mock = MagicMock(spec=StorageConfig)
    state_path = tmp_path / "state.db"
    create_valid_sqlite(state_path)

    mock_throttler_instance = MagicMock()
    mock_throttler_instance.check_status.return_with = MagicMock()
    mock_throttler_instance.check_status().was_tampered = True
    mock_throttler_class.return_value = mock_throttler_instance

    issues = DoctorEngine._diagnose_statedb(config_mock, state_path, "real-deployment-id")
    
    assert len(issues) == 1
    assert "Tamper signature mismatch" in issues[0].message
    assert issues[0].is_critical is True
    assert issues[0].can_fix is False

def test_complete_engine_diagnose_healthy_workflow(tmp_path):
    config = StorageConfig(base_dir=tmp_path)
    config.ensure_layout()

    manifest_path = tmp_path / ".muraq-kms" / "manifest.json"
    manifest_path.write_text(json.dumps({"deployment_id": "valid_id"}), encoding="utf-8")
    
    (tmp_path / ".muraq-kms" / "drs.enc").write_bytes(b"key_data")
    (tmp_path / ".muraq-kms" / "signature.enc").write_bytes(b"sig_data")
    create_valid_sqlite(config.db_path)
    create_valid_sqlite(config.state_db_path)
    create_valid_sqlite(config.audit_db_path)
    create_valid_sqlite(config.recovery_db_path)

    with patch("muraq_kms.core.throttling") as mock_throttle:
        mock_throttle.return_value.check_status.return_value.was_tampered = False
        
        report = DoctorEngine.diagnose(config)
        
        assert report.is_healthy is True
        assert len(report.issues) == 0

def test_complete_engine_diagnose_identifies_critical_vs_warning(tmp_path):
    """Verify combination paths accumulate critical blockages and fixable repairs side-by-side."""
    config = StorageConfig(base_dir=tmp_path)
    config.ensure_layout()

    create_valid_sqlite(config.db_path)

    report = DoctorEngine.diagnose(config)

    assert report.is_healthy is False
    assert report.has_critical is True 

    criticals = [i for i in report.issues if i.is_critical]
    warnings = [i for i in report.issues if not i.is_critical]

    assert len(criticals) >= 2
    assert len(warnings) >= 3

def test_diagnose_missing_signature_is_critical(tmp_path):
    config = StorageConfig(base_dir=tmp_path)
    config.ensure_layout()

    with open(config.base_dir / "manifest.json", "w") as m:
        json.dump({"deployment_id": "test-uuid", "kdf_salt_hex": "00", "deployment_salt_hex": "00"}, m)

    config.db_path.touch()
    config.audit_db_path.touch()
    config.recovery_db_path.touch()

    report = DoctorEngine.diagnose(config)
    
    assert report.is_healthy is False
    assert report.has_critical is True
    
    sig_issue = next(i for i in report.issues if i.asset == "signature.enc")
    assert sig_issue.can_fix is False
    assert sig_issue.is_critical is True

def test_diagnose_statedb_tamper_flags_critical_unfixable(tmp_path):
    config = StorageConfig(base_dir=tmp_path)
    config.ensure_layout()

    with open(config.base_dir / "manifest.json", "w") as m:
        json.dump({"deployment_id": "test-uuid", "kdf_salt_hex": "00", "deployment_salt_hex": "00"}, m)
    config.base_dir.joinpath("signature.enc").touch()
    config.db_path.touch()
    config.audit_db_path.touch()
    config.recovery_db_path.touch()
    config.state_db_path.touch()
        
    with patch("muraq_kms.core.doctor.doctor.DoctorEngine._verify_sqlite", return_value=True), \
        patch("muraq_kms.core.doctor.doctor.ThrottlingEngine") as mock_throttler_cls:
        
        mock_status = MagicMock()
        mock_status.was_tampered = True
        mock_status.is_locked = False
        
        mock_throttler = MagicMock()
        mock_throttler.check_status.return_value = mock_status
        mock_throttler_cls.return_value = mock_throttler

        report = DoctorEngine.diagnose(config)

        assert report.has_critical is True

        state_issue = next(i for i in report.issues if i.asset == "state.db")
        assert state_issue.is_critical is True
        assert state_issue.can_fix is False