from enum import Enum, auto
from typing import Optional

from muraq_kms.storage.config import StorageConfig
from muraq_kms.crypto.kdf import derive_pp_key
from muraq_kms.crypto.primitives import decrypt_envelope, split_root_secret

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
                deployment_id = manifest_data["deployment_id"]
            except (KeyError, ValueError) as e:
                raise EngineError(f"Manifest corruption detected: {str(e)}")
        
        with open(drs_path, "rb") as d:
            wrapped_drs = d.read()
        
        kwk = derive_pp_key(passphrase, kdf_salt)

        try:
            raw_drs = decrypt_envelope(wrapped_drs, kwk)
        except Exception:
            raise EngineError("Unseal failed: Invalid passphrase or corrupted payload.")
        
        rmk, ask = split_root_secret(raw_drs, deployment_salt)

        self._raw_drs = raw_drs
        self._rmk = rmk
        self._ask = ask
        self._deployment_id = deployment_id
        self._state = EngineState.UNSEALED
    

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
