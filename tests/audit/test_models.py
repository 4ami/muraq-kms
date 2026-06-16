import pytest

from pydantic import ValidationError

from muraq_kms.audit.models import AuditEntry
from muraq_kms.audit.manager import AuditManager

class TestAuditEntryValidation:

    def test_audit_entry_status_constraint_valid(self):
        """Usability: Verify lowercase statuses pass validation and normalize to uppercase."""
        entry = AuditEntry(
            action="kms:borrow",
            actor="user_01",
            details="{}",
            status="success",
            previous_hash="00000000000000000000000000000000"
        )
        assert entry.status == "SUCCESS"

    def test_audit_entry_status_constraint_invalid(self):
        """Usability: Verify arbitrary status terms are blocked by the Pydantic field validator."""
        with pytest.raises(ValidationError) as exc_info:
            AuditEntry(
                action="kms:borrow",
                actor="user_01",
                details="{}",
                status="COMPROMISED",
                previous_hash="00000000000000000000000000000000"
            )
        assert "Status must exactly match database constraint" in str(exc_info.value)

    def test_verify_chain_no_repository(self, secret_key):
        """Usability: Decoupled managers with no underlying storage pools should inherently pass verification."""
        manager = AuditManager(pool=None)
        assert manager.verify_chain_integrity_sync(secret_key) is True