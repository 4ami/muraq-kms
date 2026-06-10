import pytest
import tempfile
from pathlib import Path
from muraq_kms.storage.config import StorageConfig
from muraq_kms.cli.shell import MKMSShell

@pytest.fixture
def test_cli_shell():
    with tempfile.TemporaryDirectory() as tmpdir:
        config = StorageConfig(base_dir=Path(tmpdir))
        shell = MKMSShell(config=config)
        yield shell