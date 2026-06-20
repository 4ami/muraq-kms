import pytest
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

from muraq_kms.storage.config import StorageConfig
from muraq_kms.cli.shell import MKMSShell
from muraq_kms.cli.shells.unsealed_shell import MKMSUnsealedShell

from muraq_kms.core.engine import CoreEngine, EngineState

@pytest.fixture
def test_cli_shell():
    with tempfile.TemporaryDirectory() as tmpdir:
        config = StorageConfig(base_dir=Path(tmpdir))
        shell = MKMSShell(config=config)
        yield shell

@pytest.fixture
def prepared_engine(tmp_path):
    engine = CoreEngine(config=MagicMock(base_dir=tmp_path, state_db_path=tmp_path / "state.db"))
    
    (tmp_path / "manifest.json").write_text('{"deployment_id": "test-id"}')
    (tmp_path / "drs.enc").touch()
    (tmp_path / "signature.enc").touch()
    return engine

@pytest.fixture
def test_unsealed_shell(prepared_engine):
    with tempfile.TemporaryDirectory() as tmpdir:
        config = StorageConfig(Path(tmpdir))
        prepared_engine._state = EngineState.UNSEALED
        prepared_engine._ask = b"mock_ask_bytes_32_length________"
        prepared_engine._rmk = b"mock_rmk_bytes_32_length________"
        prepared_engine._deployment_id = "test-id"

        shell = MKMSUnsealedShell(config, prepared_engine)
        shell.key_manager = MagicMock()
        shell._actor = "operator-dev"
        yield shell