from datetime import datetime, timezone

from muraq_kms.audit.manager import AuditManager
from muraq_kms.audit.repository import AuditRepository
from muraq_kms.audit.models import AuditEntry
from muraq_kms.audit.audit_errors import AuditIntegrityError

import pytest

@pytest.mark.asyncio
class TestAuditFlowsAsync:
    async def test_verify_chain_integrity_async_success(self, mock_pool, secret_key):
        """Security: Validation should pass seamlessly with a pristine unmodified sequential chain."""
        repo = AuditRepository(mock_pool)
        manager = AuditManager(mock_pool)
        manager.repo = repo

        t1, t2 = 1718539200.0, 1718539210.0
        
        e1 = AuditEntry(action="kms:create", actor="root", details="{}", status="SUCCESS", 
                        previous_hash="00000000000000000000000000000000", timestamp=datetime.fromtimestamp(t1, tz=timezone.utc))
        h1 = manager.compute_runtime_hash(e1, secret_key)
        
        e2 = AuditEntry(action="kms:borrow", actor="root", details="{}", status="SUCCESS", 
                        previous_hash=h1, timestamp=datetime.fromtimestamp(t2, tz=timezone.utc))
        h2 = manager.compute_runtime_hash(e2, secret_key)

        mock_db_rows = [
            (t1, "kms:create", "root", "{}", "SUCCESS", "00000000000000000000000000000000", h1, 1),
            (t2, "kms:borrow", "root", "{}", "SUCCESS", h1, h2, 2)
        ]

        mock_pool.async_backend.fetchall.return_value = mock_db_rows

        result = await manager.verify_chain_integrity_async(secret_key)
        assert result[0] is True
        mock_pool.async_backend.fetchall.assert_called_once()

    async def test_verify_chain_integrity_async_chain_break(self, mock_pool, secret_key):
        """Security: Intercepting and breaking the previous_hash backlink mapping must raise an AuditIntegrityError."""
        repo = AuditRepository(mock_pool)
        manager = AuditManager(mock_pool)
        manager.repo = repo

        t1, t2 = 1718539200.0, 1718539210.0
        
        e1 = AuditEntry(action="kms:create", actor="root", details="{}", status="SUCCESS", 
                        previous_hash="00000000000000000000000000000000", timestamp=datetime.fromtimestamp(t1, tz=timezone.utc))
        h1 = manager.compute_runtime_hash(e1, secret_key)
        
        mock_db_rows = [
            (t1, "kms:create", "root", "{}", "SUCCESS", "00000000000000000000000000000000", h1, 1),
            (t2, "kms:borrow", "root", "{}", "SUCCESS", "INVALID_FORGED_POINTER_HASH", "some_hash", 2)
        ]

        mock_pool.async_backend.fetchall.return_value = mock_db_rows

        with pytest.raises(AuditIntegrityError) as exc_info:
            await manager.verify_chain_integrity_async(secret_key)
        assert "Audit chain break detected at row ID 2" in str(exc_info.value)

    async def test_verify_chain_integrity_async_tampering(self, mock_pool, secret_key):
        """Security: Modifying payload data post-write while preserving old hashes must trigger validation errors."""
        repo = AuditRepository(mock_pool)
        manager = AuditManager(mock_pool)
        manager.repo = repo

        t1 = 1718539200.0
        
        e1 = AuditEntry(action="policy:allow", actor="root", details='{"resource": "key_0"}', status="SUCCESS", 
                        previous_hash="00000000000000000000000000000000", timestamp=datetime.fromtimestamp(t1, tz=timezone.utc))
        h1 = manager.compute_runtime_hash(e1, secret_key)
        
        mock_db_rows = [
            (t1, "policy:allow", "root", '{"resource": "key_999"}', "SUCCESS", "00000000000000000000000000000000", h1, 1)
        ]

        mock_pool.async_backend.fetchall.return_value = mock_db_rows

        with pytest.raises(AuditIntegrityError) as exc_info:
            await manager.verify_chain_integrity_async(secret_key)
        assert "chain break detected at row ID 1" in str(exc_info.value)