import pytest
from unittest.mock import MagicMock, AsyncMock

@pytest.fixture
def secret_key():
    """Canonical HMAC secret key used across the KMS audit domain."""
    return b"super_secret_genesis_hmac_key_12345"

@pytest.fixture
def mock_pool():
    """Generates an insulated storage pool mocking out transaction contexts and cursors."""
    pool = MagicMock()
    
    # Mock Sync Architecture
    pool.sync_backend = MagicMock()
    pool.sync_backend.transaction.return_value.__enter__ = MagicMock()
    pool.sync_backend.transaction.return_value.__exit__ = MagicMock()
    
    # Mock Async Architecture
    pool.async_backend = MagicMock()
    pool.async_backend.fetchone = AsyncMock()
    pool.async_backend.fetchall = AsyncMock()
    
    async_tx = AsyncMock()
    async_tx.__aenter__ = AsyncMock()
    async_tx.__aexit__ = AsyncMock()
    pool.async_backend.transaction.return_value = async_tx
    
    return pool