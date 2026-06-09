import tempfile
import pytest
import shutil
from pathlib import Path

from muraq_kms.storage.config import StorageConfig
from muraq_kms.core.bootstrap import bootstrap

@pytest.fixture
def isolated_env(valid_passphrase):
    tmp_dir = tempfile.mkdtemp()
    cfg = StorageConfig(base_dir=Path(tmp_dir))

    bootstrap(cfg, valid_passphrase, force=True)

    yield cfg, valid_passphrase

    shutil.rmtree(tmp_dir)
