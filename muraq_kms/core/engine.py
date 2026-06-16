from enum import Enum, auto
from typing import Any, Optional, Dict

# from muraq_kms.audit.repository import AuditRepository

from muraq_kms.storage.config import StorageConfig
# from muraq_kms.storage.pool import StoragePool

from muraq_kms.crypto.kdf import derive_pp_key
from muraq_kms.crypto.primitives import decrypt_envelope, split_root_secret
from muraq_kms.crypto.system import verify_manifest_signature

from muraq_kms.core.exceptions import EngineError

import json

class EngineState(Enum):
    SEALED = auto()
    UNSEALED = auto()

class CoreEngine:
    def __init__(self, config:Optional[StorageConfig] = None) -> None:
        self.config:StorageConfig = config or StorageConfig.from_env()
        self._state:EngineState = EngineState.SEALED

        self._raw_drs:Optional[bytes] = None
        self._rmk:Optional[bytes] = None
        self._ask:Optional[bytes] = None
        self._deployment_id:Optional[str] = None
    
    @property
    def state(self) -> EngineState:
        return self._state

    @property
    def deployment_id(self) -> Optional[str]:
        return self._deployment_id

    def get_ask(self) -> bytes:
        """Access the Audit Signing Key if unsealed."""
        if self._state != EngineState.UNSEALED or self._ask is None:
            raise EngineError("Engine is sealed. Access to ASK denied.")
        return self._ask
    
    def get_rmk(self) -> bytes:
        """Access the Recovery Master Key if unsealed."""
        if self._state != EngineState.UNSEALED or self._rmk is None:
            raise EngineError("Engine is sealed. Access to RMK denied.")
        return self._rmk
    
    def unseal(self, passphrase:str) -> None:
        """
        Unseals the KMS engine, reconstructing the volatile cryptographic boundary.
        Re-stretches the passphrase via Argon2id, decrypts the DRS, and splits secrets.
        """
        if self._state == EngineState.UNSEALED:
            return
        
        manifest_path = self.config.base_dir / "manifest.json"
        drs_path = self.config.base_dir / "drs.enc"

        if not manifest_path.exists() or not drs_path.exists():
            raise EngineError("Engine cannot be unsealed: Missing manifest or DRS artifacts.")
        
        with open(manifest_path, "r", encoding="utf-8") as m:
            manifest_data = json.load(m)

            try:
                kdf_salt = bytes.fromhex(manifest_data["kdf_salt_hex"])
                deployment_salt = bytes.fromhex(manifest_data["deployment_salt_hex"])
            except (KeyError, ValueError) as e:
                raise EngineError(f"Manifest corruption detected: {str(e)}")
        
        with open(drs_path, "rb") as d:
            wrapped_drs = d.read()
        
        kwk = derive_pp_key(passphrase, kdf_salt)

        try:
            raw_drs = decrypt_envelope(wrapped_drs, kwk)
        except Exception:
            raise EngineError("Unseal failed: Invalid passphrase or corrupted payload.")
        
        try:
            rmk, ask = split_root_secret(raw_drs, deployment_salt)
            self._raw_drs = raw_drs
            self._rmk = rmk
            self._ask = ask

            self.verify_on_unseal(manifest_data, kwk)
            self._state = EngineState.UNSEALED
        except Exception:
            self.seal()
            raise
        finally:
            if 'kwk' in locals() and kwk:
                kwk = b"\x00" * len(kwk)
            if 'raw_drs' in locals() and raw_drs:
                raw_drs = b"\x00" * len(raw_drs)
            if 'rmk' in locals() and rmk:
                rmk = b"\x00" * len(rmk)
            if 'ask' in locals() and ask:
                ask = b"\x00" * len(ask)
    

    def seal(self) -> None:
        if self._raw_drs is not None:
            self._raw_drs = b"\x00" * len(self._raw_drs)
        if self._rmk is not None:
            self._rmk = b"\x00" * len(self._rmk)
        if self._ask is not None:
            self._ask = b"\x00" * len(self._ask)
        
        self._raw_drs = None
        self._rmk = None
        self._ask = None
        self._deployment_id = None
        self._state = EngineState.SEALED
    
    def verify_on_unseal(self, manifest:Dict[str, Any], kwk:bytes) -> None:
        with open(self.config.base_dir / "signature.enc", 'rb') as s:
            wrapped_signature = s.read()
        
        decrypted_signature = decrypt_envelope(wrapped_signature, kwk)
        payload = json.loads(decrypted_signature.decode('utf-8'))

        if not verify_manifest_signature(manifest, bytes.fromhex(payload['signature']), self._raw_drs):
            raise EngineError("CRITICAL: manifest.json has been tampered with or modified!")

        if payload["trusted_deployment_id"] != manifest["deployment_id"]:
            print("⚠️ [!] Identity spoofing detected! Initiating manifest auto-healing sequence...")
            id = payload['trusted_deployment_id']
            manifest['deployment_id'] = id
            with open(self.config.base_dir / "manifest.json", "w", encoding="utf-8") as m:
                json.dump(manifest, m, indent=4)
            print("✨ [+] manifest.json has been recovered and synced with the platform identity anchor.")
            raise EngineError("CRITICAL: Manifest deployment identity spoofing detected!")

        self._deployment_id = payload['trusted_deployment_id']