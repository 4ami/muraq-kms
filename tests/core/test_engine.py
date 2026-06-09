import pytest

from pathlib import Path
import tempfile

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
    """Verify unseal breaks safely if run on an empty system directory structure."""
    with tempfile.TemporaryDirectory() as empty_dir:
        config = StorageConfig(base_dir=Path(empty_dir))
        engine = CoreEngine(config=config)
        
        with pytest.raises(EngineError, match="Missing manifest or DRS artifacts"):
            engine.unseal("any_passphrase")