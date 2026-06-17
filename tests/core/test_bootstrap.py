import hashlib
import hmac
import json
import pytest

from muraq_kms.storage.sqlite import SQLiteStorage
from muraq_kms.core.bootstrap import bootstrap, AlreadyInitializedError
from muraq_kms.crypto.kdf import derive_pp_key
from muraq_kms.crypto.primitives import decrypt_envelope, split_root_secret
from muraq_kms.core.actor import cli_actor

def test_bootstrap_happy_path(storage_config, valid_passphrase):
    """
    Verifies the system can be completely initialized from scratch.
    Validates filesystem layout creation, manifest schema, and storage readiness.
    """
    bootstrap(config=storage_config, passphrase=valid_passphrase, force=False)

    manifest_path = storage_config.base_dir / "manifest.json"
    drs_path = storage_config.base_dir / "drs.enc"

    assert manifest_path.exists()
    assert drs_path.exists()
    assert storage_config.db_path.exists()
    assert storage_config.audit_db_path.exists()
    assert storage_config.recovery_db_path.exists()

    with open(manifest_path, "r", encoding="utf-8") as m:
        manifest_data = json.load(m)
        
    assert manifest_data["version"] is not None
    assert manifest_data["deployment_id"].startswith("mkms_did_")
    assert "kdf_salt_hex" in manifest_data
    assert "deployment_salt_hex" in manifest_data
    assert "initialized_at" in manifest_data

    storage = SQLiteStorage(config=storage_config)
    actor = f"[MKMS-bootstrap]-{cli_actor()}"
    try:
        row = storage.fetchone(
            "SELECT action, actor, status, previous_hash FROM audit_log WHERE action = ?;",
            ("MURAQ-KMS-INIT",),
            domain="audit"
        )
        assert row is not None
        assert row == ("MURAQ-KMS-INIT", actor, "SUCCESS", "00000000000000000000000000000000")
    finally:
        storage.close()


def test_bootstrap_enforces_strict_idempotency(storage_config, valid_passphrase):
    bootstrap(config=storage_config, passphrase=valid_passphrase, force=False)

    with pytest.raises(AlreadyInitializedError) as exc_info:
        bootstrap(config=storage_config, passphrase=valid_passphrase, force=False)
        
    assert "already initialized" in str(exc_info.value)


def test_bootstrap_force_override_purges_old_state(storage_config, valid_passphrase):
    bootstrap(config=storage_config, passphrase=valid_passphrase, force=False)
    
    with open(storage_config.base_dir / "manifest.json", "r") as m:
        initial_manifest = json.load(m)
    initial_did = initial_manifest["deployment_id"]

    new_passphrase = "Completely-Different-Passphrase-2026!!!"
    bootstrap(config=storage_config, passphrase=new_passphrase, force=True)

    with open(storage_config.base_dir / "manifest.json", "r") as m:
        fresh_manifest = json.load(m)
    fresh_did = fresh_manifest["deployment_id"]

    assert initial_did != fresh_did 
    assert initial_manifest["kdf_salt_hex"] != fresh_manifest["kdf_salt_hex"]


def test_genesis_audit_cryptographic_verification(storage_config, valid_passphrase):
    bootstrap(config=storage_config, passphrase=valid_passphrase, force=False)

    with open(storage_config.base_dir / "manifest.json", "r") as m:
        manifest = json.load(m)
    with open(storage_config.base_dir / "drs.enc", "rb") as d:
        wrapped_drs = d.read()

    kdf_salt = bytes.fromhex(manifest["kdf_salt_hex"])
    deployment_salt = bytes.fromhex(manifest["deployment_salt_hex"])

    kwk = derive_pp_key(valid_passphrase, kdf_salt)
    raw_drs = decrypt_envelope(wrapped_drs, kwk)
    _, ask = split_root_secret(raw_drs, deployment_salt)

    storage = SQLiteStorage(config=storage_config)
    try:
        row = storage.fetchone(
            "SELECT timestamp, action, actor, details, status, previous_hash, hash "
            "FROM audit_log WHERE action = ?;",
            ("MURAQ-KMS-INIT",),
            domain="audit"
        )
        assert row is not None
        db_ts, db_action, db_actor, db_details, db_status, db_prev_hash, db_entry_hash = row

        verification_msg = f"{db_ts}|{db_action}|{db_actor}|{db_details}|{db_status}|{db_prev_hash}"
        
        calculated_hash = hmac.new(
            key=ask,
            msg=verification_msg.encode("utf-8"),
            digestmod=hashlib.sha256
        ).hexdigest()

        assert db_entry_hash == calculated_hash

    finally:
        storage.close()