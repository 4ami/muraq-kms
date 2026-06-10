import tempfile
import pytest
import shutil
from pathlib import Path

import json

from muraq_kms.storage.config import StorageConfig
from muraq_kms.core.bootstrap import bootstrap, bootstrap_storage

@pytest.fixture
def isolated_env(valid_passphrase):
    tmp_dir = tempfile.mkdtemp()
    cfg = StorageConfig(base_dir=Path(tmp_dir))

    bootstrap(cfg, valid_passphrase, force=True)

    yield cfg, valid_passphrase

    shutil.rmtree(tmp_dir)

@pytest.fixture
def initialized_core_context():
    """Provides a realistic layout configuration populated with a valid mock manifest."""
    with tempfile.TemporaryDirectory() as tmpdir:
        base_dir = Path(tmpdir) / ".muraq-kms"
        config = StorageConfig(base_dir=base_dir)
        config.ensure_layout()
        
        bootstrap_storage(config)
        
        manifest_data = {
            "deployment_id": "test-deployment-id-uuid-4444",
            "kdf_salt_hex": "aabbccddeeff0011",
            "deployment_salt_hex": "1122334455667788"
        }
        with open(base_dir / "manifest.json", "w", encoding="utf-8") as m:
            json.dump(manifest_data, m)
            
        yield config