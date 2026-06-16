from datetime import datetime, timezone
import hmac
import hashlib
import json
from typing import List, Optional, Any
from muraq_kms.audit.models import AuditEntry
from muraq_kms.audit.repository import AuditRepository
from muraq_kms.audit.audit_errors import AuditIntegrityError

from muraq_kms.storage.pool import StoragePool

class AuditManager:
    """
    Manages runtime append-only audit records, completely matching the signature 
    and serialization mechanics of the system's genesis initialization pass.
    """
    def __init__(self, pool:Optional[StoragePool] = None) -> None:
        self.pool = pool
        self.repo = AuditRepository(self.pool) if pool else None
    
    def compute_runtime_hash(self, entry:AuditEntry, ask:bytes) -> str:
        """
        Computes the HMAC-SHA256 over a pipe-delimited string payload, matching
        the exact canonical format used during the system genesis boot sequence.
        """
        msg = f"{entry.timestamp.timestamp()}|{entry.action}|{entry.actor}|{entry.details}|{entry.status}|{entry.previous_hash}"

        return hmac.new(
            key=ask,
            msg=msg.encode('utf-8'),
            digestmod=hashlib.sha256
        ).hexdigest()
    
    async def log_event_async(self, action:str, actor:str, details:dict, timestamp:Optional[datetime], status:str, ask:bytes) -> AuditEntry:
        prev_hash = "00000000000000000000000000000000"
        if self.repo:
            latest = await self.repo.fetch_latest_record_async()
            if latest and ("hash" in latest):
                prev_hash = latest['hash']

        entry = AuditEntry(
            action=action,
            actor=actor,
            details=json.dumps(details, sort_keys=True),
            status=status,
            previous_hash=prev_hash,
        )
        if timestamp:
            entry.timestamp = timestamp
        entry.hash=self.compute_runtime_hash(entry, ask)

        row = None
        if self.repo:
            row = await self.repo.append_entry_async(
                timestamp=entry.timestamp.timestamp(),
                action=entry.action,
                actor=entry.actor,
                details=entry.details,
                status=entry.status,
                previous_hash=entry.previous_hash,
                entry_hash=entry.hash
            )
            entry.id = row['_id']
        return entry
    
    def log_event_sync(self, action:str, actor:str, details:dict, timestamp:Optional[datetime], status:str, ask:bytes) -> AuditEntry:
        prev_hash = "00000000000000000000000000000000"
        if self.repo:
            latest = self.repo.fetch_latest_record_sync()
            if latest and ("hash" in latest):
                prev_hash = latest['hash']

        entry = AuditEntry(
            action=action,
            actor=actor,
            details=json.dumps(details, sort_keys=True),
            status=status,
            previous_hash=prev_hash,
        )
        if timestamp:
            entry.timestamp = timestamp
        entry.hash = self.compute_runtime_hash(entry, ask)

        row = None
        if self.repo:
            row = self.repo.append_entry_sync(
                timestamp=entry.timestamp.timestamp(),
                action=entry.action,
                actor=entry.actor,
                details=entry.details,
                status=entry.status,
                previous_hash=entry.previous_hash,
                entry_hash=entry.hash
            )
            entry.id = row['_id']
        return entry
    
    def _verfication_loop(self, rows:List[tuple[Any, ...]], ask:bytes) -> bool:
        expected_previous_hash = "00000000000000000000000000000000"

        for row in rows:
            entry = AuditEntry(
                id= row[7],
                timestamp=datetime.fromtimestamp(float(row[0]), tz=timezone.utc),
                action=row[1],
                actor=row[2],
                details=row[3],
                status=row[4],
                previous_hash=row[5],
                hash=row[6]
            )

            if entry.previous_hash != expected_previous_hash:
                raise AuditIntegrityError(
                    f"CRITICAL: Audit chain break detected at row ID {entry.id}! "
                    f"Record expects parent hash '{entry.previous_hash}', but actual calculated history was '{expected_previous_hash}'."
                )

            calculated_hash = self.compute_runtime_hash(entry, ask)

            if not hmac.compare_digest(entry.hash, calculated_hash):
                 raise AuditIntegrityError(
                    f"CRITICAL: Record tampering discovered at row ID {entry.id}! "
                    f"Database hash payload value has been modified post-write."
                )
            
            expected_previous_hash = entry.hash
        
        return True

    async def verify_chain_integrity_async(self, ask:bytes) -> bool:
        if not self.repo:
            return True
        
        rows = await self.repo.all_async(asc=True)
        return self._verfication_loop(rows, ask)
    
    def verify_chain_integrity_sync(self, ask:bytes) -> bool:
        if not self.repo:
            return True
        rows = self.repo.all_sync(asc=True)
        return self._verfication_loop(rows, ask)