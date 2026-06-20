import pytest

from datetime import datetime, timezone

from muraq_kms.audit.manager import AuditManager
from muraq_kms.audit.models import AuditEntry
from muraq_kms.audit.audit_errors import AuditIntegrityError

class TestAuditSecurityIntegrity:
    def test_verification_loop_valid_unmodified_chain(self, secret_key):
        """Security: Pristine sequential logs with exact matching HMACs must pass verification."""
        manager = AuditManager(pool=None)
        t1, t2 = 1718539200.0, 1718539210.0
        
        e1 = AuditEntry(action="kms:create", actor="root", details="{}", status="SUCCESS", 
                        previous_hash="00000000000000000000000000000000", timestamp=datetime.fromtimestamp(t1, tz=timezone.utc))
        h1 = manager.compute_runtime_hash(e1, secret_key)
        
        e2 = AuditEntry(action="kms:borrow", actor="root", details="{}", status="SUCCESS", 
                        previous_hash=h1, timestamp=datetime.fromtimestamp(t2, tz=timezone.utc))
        h2 = manager.compute_runtime_hash(e2, secret_key)

        rows = [
            (t1, "kms:create", "root", "{}", "SUCCESS", "00000000000000000000000000000000", h1, 1),
            (t2, "kms:borrow", "root", "{}", "SUCCESS", h1, h2, 2)
        ]

        assert manager._verfication_loop(rows, secret_key)[0] is True
    
    def test_verification_loop_chain_link_break(self, secret_key):
        """Security: Intercepting and breaking the previous_hash backlink mapping must raise an AuditIntegrityError."""
        manager = AuditManager(pool=None)
        t1, t2 = 1718539200.0, 1718539210.0
        
        e1 = AuditEntry(action="kms:create", actor="root", details="{}", status="SUCCESS", 
                        previous_hash="00000000000000000000000000000000", timestamp=datetime.fromtimestamp(t1, tz=timezone.utc))
        h1 = manager.compute_runtime_hash(e1, secret_key)
        
        rows = [
            (t1, "kms:create", "root", "{}", "SUCCESS", "00000000000000000000000000000000", h1, 1),
            (t2, "kms:borrow", "root", "{}", "SUCCESS", "MALICIOUS_FORGED_LINK_HASH", "some_hash", 2)
        ]

        with pytest.raises(AuditIntegrityError) as exc_info:
            manager._verfication_loop(rows, secret_key)
        assert "Audit chain break detected at row ID 2" in str(exc_info.value)
    
    def test_verification_loop_row_payload_tampering(self, secret_key):
        """Security: Modifying details values post-write while retaining the authentic signature hash must raise an AuditIntegrityError."""
        manager = AuditManager(pool=None)
        t1 = 1718539200.0
        
        e1 = AuditEntry(action="policy:allow", actor="root", details='{"resource": "key_0"}', status="SUCCESS", 
                        previous_hash="00000000000000000000000000000000", timestamp=datetime.fromtimestamp(t1, tz=timezone.utc))
        h1 = manager.compute_runtime_hash(e1, secret_key)
        
        rows = [
            (t1, "policy:allow", "root", '{"resource": "key_9999"}', "SUCCESS", "00000000000000000000000000000000", h1, 1)
        ]

        with pytest.raises(AuditIntegrityError) as exc_info:
            manager._verfication_loop(rows, secret_key)
        assert "chain break detected at row ID 1" in str(exc_info.value)