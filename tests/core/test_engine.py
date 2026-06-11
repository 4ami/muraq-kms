import pytest

from pathlib import Path
import tempfile
from unittest.mock import patch, MagicMock

import json

from muraq_kms.storage.config import StorageConfig
from muraq_kms.core.bootstrap import bootstrap
from muraq_kms.core.engine import CoreEngine, EngineState
from muraq_kms.core.exceptions import EngineError


def test_engine_initial_state_is_sealed():
    """Verify that an instantiated core engine naturally defaults to a secure SEALED state."""
    config = StorageConfig(base_dir=Path("/tmp/non_existent_path_mock"))
    engine = CoreEngine(config=config)
    assert engine.state == EngineState.SEALED
    
    with pytest.raises(EngineError, match="Engine is sealed"):
        engine.get_ask()
        
    with pytest.raises(EngineError, match="Engine is sealed"):
        engine.get_rmk()

def test_engine_successful_unseal_lifecycle(isolated_env):
    """Verify that a valid passphrase unseals the engine and unlocks memory key boundaries."""
    config, passphrase = isolated_env
    engine = CoreEngine(config=config)
    
    assert engine.state == EngineState.SEALED
    
    engine.unseal(passphrase)
    
    assert engine.state == EngineState.UNSEALED
    assert engine.deployment_id.startswith("mkms_did_")
    
    ask = engine.get_ask()
    rmk = engine.get_rmk()
    
    assert isinstance(ask, bytes) and len(ask) == 32
    assert isinstance(rmk, bytes) and len(rmk) == 32
    assert ask != rmk

def test_engine_unseal_fails_with_invalid_passphrase(isolated_env):
    """Verify that wrong passphrases are aggressively rejected and maintain system seal."""
    config, _ = isolated_env
    engine = CoreEngine(config=config)
    
    with pytest.raises(EngineError, match="Unseal failed: Invalid passphrase"):
        engine.unseal("WrongPassphrase123!")
        
    assert engine.state == EngineState.SEALED
    assert engine.deployment_id is None

def test_engine_seal_wipes_transient_memory_structures(isolated_env):
    """Verify that sealing the engine returns the system to safety and leaves no remaining traces."""
    config, passphrase = isolated_env
    engine = CoreEngine(config=config)
    
    engine.unseal(passphrase)
    assert engine.state == EngineState.UNSEALED
    
    engine.seal()
    
    assert engine.state == EngineState.SEALED
    assert engine.deployment_id is None
    
    with pytest.raises(EngineError, match="Engine is sealed"):
        engine.get_ask()

def test_engine_unseal_fails_without_bootstrapped_artifacts():
    with tempfile.TemporaryDirectory() as empty_dir:
        config = StorageConfig(base_dir=Path(empty_dir))
        engine = CoreEngine(config=config)
        
        with pytest.raises(EngineError, match="Missing manifest or DRS artifacts"):
            engine.unseal("any_passphrase")

@patch("muraq_kms.core.engine.derive_pp_key")
@patch("muraq_kms.core.engine.decrypt_envelope")
@patch("muraq_kms.core.engine.split_root_secret")
@patch("muraq_kms.core.engine.verify_manifest_signature")
def test_unseal_state_protection_and_zeroization_on_failure(
    mock_verify_sig, mock_split, mock_decrypt, mock_derive, isolated_env
):
    config, _ = isolated_env
    with open(config.base_dir / "manifest.json", "w") as m:
        json.dump({"deployment_id": "true-id", "kdf_salt_hex": "00", "deployment_salt_hex": "00"}, m)
    (config.base_dir / "drs.enc").write_bytes(b"wrapped-drs")
    (config.base_dir / "signature.enc").write_bytes(b"wrapped-sig")

    mock_derive.return_value = b"kwk-key-material-32-bytes-long"
    mock_decrypt.side_effect = [b"raw_drs_bytes", b'{"trusted_deployment_id": "true-id", "signature": "aabb"}']
    mock_split.return_value = (b"rmk_bytes", b"ask_bytes")
    
    mock_verify_sig.return_value = False

    engine = CoreEngine(config=config)
    
    with pytest.raises(EngineError, match="CRITICAL: manifest.json has been tampered with"):
        engine.unseal("master_passphrase")

    assert engine.state == EngineState.SEALED
    assert engine._raw_drs is None
    assert engine._rmk is None
    assert engine._ask is None

@patch("muraq_kms.core.engine.derive_pp_key")
@patch("muraq_kms.core.engine.decrypt_envelope")
@patch("muraq_kms.core.engine.split_root_secret")
@patch("muraq_kms.core.engine.verify_manifest_signature")
def test_unseal_auto_heals_manifest_spoofing(
    mock_verify_sig, mock_split, mock_decrypt, mock_derive, isolated_env
):
    config, _ = isolated_env
    manifest_path = config.base_dir / "manifest.json"
    
    with open(manifest_path, "w") as m:
        json.dump({"deployment_id": "spoofed-attacker-id", "kdf_salt_hex": "00", "deployment_salt_hex": "00"}, m)
    (config.base_dir / "drs.enc").write_bytes(b"wrapped-drs")
    (config.base_dir / "signature.enc").write_bytes(b"wrapped-sig")

    mock_derive.return_value = b"kwk"
    mock_decrypt.side_effect = [b"raw_drs", b'{"trusted_deployment_id": "legit-prod-id", "signature": "aabb"}']
    mock_split.return_value = (b"rmk", b"ask")
    mock_verify_sig.return_value = True

    engine = CoreEngine(config=config)

    with pytest.raises(EngineError, match="identity spoofing detected"):
        engine.unseal("master_passphrase")

    with open(manifest_path, "r") as m:
        healed_data = json.load(m)
    assert healed_data["deployment_id"] == "legit-prod-id"