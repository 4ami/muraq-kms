import shutil
from muraq_kms.storage.config import StorageConfig
from muraq_kms.storage.migrate import MigrationRunner
from muraq_kms.storage.sqlite import SQLiteStorage
from typing import Optional

from uuid import uuid4
from muraq_kms.crypto.kdf import derive_pp_key
from muraq_kms.crypto.primitives import generate_secure_bytes, encrypt_envelope, split_root_secret

from pathlib import Path

import hmac
import hashlib

import json
from datetime import datetime, timezone
from muraq_kms import __version__

from muraq_kms.core.exceptions import AlreadyInitializedError

def enforce_idempotency(config: StorageConfig, force:bool) -> tuple[Path, Path]:
    manifest_path = config.base_dir / "manifest.json"
    drs_path = config.base_dir / "drs.enc"

    if manifest_path.exists() or drs_path.exists():
        if not force:
            raise AlreadyInitializedError()
    
    if config.base_dir.exists():
        shutil.rmtree(config.base_dir)

    return manifest_path, drs_path



def bootstrap_storage(config: Optional[StorageConfig] = None) -> None:
    """
    Process-level bootstrap: ensure layout, apply pending migrations, return storage.

    Call from muraq-kms init, daemon startup, or doctor — not on bare import.
    """
    cfg = config or StorageConfig.from_env()
    for db_file, domain in [
        (cfg.db_path, "keys_db"),
        (cfg.audit_db_path, "audit_db"),
        (cfg.recovery_db_path, "recovery_db")
    ]:
        runner = MigrationRunner(db_path=db_file, domain=domain)
        try:
            runner.upgrade()
        finally:
            runner.close()


def build_drs(drs_path:Path, wrapped_drs:bytes) -> None:
    with open(drs_path, "wb") as d:
        d.write(wrapped_drs)


def build_manifest(
    manifest_path:Path, 
    deployment_id:str,
    kdf_salt:bytes,
    deployment_salt:bytes,
) -> dict[str, ...]:
    manifest_data = {
        "version": f"v{__version__}" if not __version__.startswith('v') else __version__,
        "deployment_id": deployment_id,
        "kdf_salt_hex": kdf_salt.hex(),
        "deployment_salt_hex":deployment_salt.hex(),
        "initialized_at":datetime.now(tz=timezone.utc).isoformat(),
    }

    with open(manifest_path, "w", encoding="utf-8") as m:
        json.dump(manifest_data, m, indent=4)
    
    return manifest_data

def genesis_audit(cfg:StorageConfig, data:dict[str, ...], ask:bytes) -> bool:
    storage = SQLiteStorage(config=cfg)

    try:
        timestamp = data["initialized_at"]
        action = "MURAQ-KMS-INIT"
        actor = "SYSTEM"
        details = json.dumps({"deployment_id": data["deployment_id"]})  # <-- FIXED: json.dumps
        status = "SUCCESS"
        previous_hash = "00000000000000000000000000000000"

        msg = f"{timestamp}|{action}|{actor}|{details}|{status}|{previous_hash}"
        entry_hash = hmac.new(
            key=ask,
            msg=msg.encode("utf-8"),
            digestmod=hashlib.sha256,
        ).hexdigest()

        storage.append_audit_entry(
            timestamp=timestamp,
            action=action,
            actor=actor,
            details=details,
            status=status,
            previous_hash=previous_hash,
            entry_hash=entry_hash
        )
    finally:
        storage.close()


def bootstrap(config:StorageConfig, passphrase:str, force:bool = False) -> None:
    manifest_path, drs_path = enforce_idempotency(config=config, force=force)

    config.ensure_layout()

    bootstrap_storage(config=config)

    deployment_id:str = f"mkms_did_{str(uuid4())}"
    raw_drs = generate_secure_bytes(32)
    kdf_salt = generate_secure_bytes(16)
    deployment_salt = generate_secure_bytes(32)

    kwk = derive_pp_key(passphrase, kdf_salt)

    wrapper_drs = encrypt_envelope(raw_drs, kwk)

    _, ask = split_root_secret(raw_drs, deployment_salt)

    manifest_data = build_manifest(manifest_path, deployment_id, kdf_salt, deployment_salt)

    build_drs(drs_path, wrapper_drs)

    genesis_audit(config, manifest_data, ask)
