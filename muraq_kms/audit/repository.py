from typing import Optional, Any, List
from muraq_kms.storage.pool import StoragePool

class AuditRepository:
    """
    Encapsulates all SQL query definitions and transactions specifically 
    concerning the audit trail database ledger.
    """
    def __init__(self, pool:StoragePool) -> None:
        self.pool = pool
    
    async def fetch_latest_record_async(self) -> Optional[dict[str, Any]]:
        sql = """
        SELECT timestamp, action, actor, details, status, previous_hash, hash
        FROM audit_log
        ORDER BY timestamp DESC, _id DESC
        LIMIT 1;
        """

        row = await self.pool.async_backend.fetchone(sql, (), domain='audit')

        if not row: return None
        
        return {
            "timestamp": row[0], "action": row[1], "actor": row[2],
            "details": row[3], "status": row[4], "previous_hash": row[5],
            "hash": row[6]
        }
    
    def fetch_latest_record_sync(self) -> Optional[dict[str, Any]]:
        sql = """
        SELECT timestamp, action, actor, details, status, previous_hash, hash
        FROM audit_log
        ORDER BY timestamp DESC, _id DESC
        LIMIT 1;
        """

        row = self.pool.sync_backend.fetchone(sql, (), domain='audit')

        if not row: return None
        
        return {
            "timestamp": row[0], "action": row[1], "actor": row[2],
            "details": row[3], "status": row[4], "previous_hash": row[5],
            "hash": row[6]
        }
    
    async def append_entry_async(self, timestamp: float, action: str, actor: str,
        details: str, status: str, previous_hash: str, entry_hash: str) -> dict[str, Any]:
        sql = """
            INSERT INTO audit_log
            (timestamp, action, actor, details, status, previous_hash, hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            RETURNING _id, timestamp, action, actor, details, status, previous_hash, hash;
            """
        
        row = None
        async with self.pool.async_backend.transaction(domain='audit') as conn:
            cursor = conn.execute(
                sql,
                (timestamp, action, actor, details, status, previous_hash, entry_hash),
            )
            row = cursor.fetchone()

        if not row:
            raise RuntimeError("Failed to insert audit entry.")
        
        return {
            "_id": row[0], "timestamp": row[1], "action": row[2],
            "actor": row[3], "details": row[4], "status": row[5],
            "previous_hash": row[6], "hash": row[7]
        }
    
    def append_entry_sync(self, timestamp: float, action: str, actor: str,
        details: str, status: str, previous_hash: str, entry_hash: str) -> dict[str, Any]:
        sql = """
            INSERT INTO audit_log
            (timestamp, action, actor, details, status, previous_hash, hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            RETURNING _id, timestamp, action, actor, details, status, previous_hash, hash;
            """
        
        row = None
        with self.pool.sync_backend.transaction(domain='audit') as conn:
            cursor = conn.execute(
                sql,
                (timestamp, action, actor, details, status, previous_hash, entry_hash),
            )
            row = cursor.fetchone()

        if not row:
            raise RuntimeError("Failed to insert audit entry.")
        
        return {
            "_id": row[0], "timestamp": row[1], "action": row[2],
            "actor": row[3], "details": row[4], "status": row[5],
            "previous_hash": row[6], "hash": row[7]
        }
    
    async def all_async(self, asc:bool = True) -> List[tuple[Any, ...]]:
        sql = f"""
        SELECT timestamp, action, actor, details, status, previous_hash, hash, _id
        FROM audit_log
        ORDER BY _id {"ASC" if asc else "DESC"};
        """
        return await self.pool.async_backend.fetchall(sql, (), domain='audit')

    def all_sync(self, asc:bool = True) -> List[tuple[Any, ...]]:
        sql = f"""
        SELECT timestamp, action, actor, details, status, previous_hash, hash, _id
        FROM audit_log
        ORDER BY _id {"ASC" if asc else "DESC"};
        """
        return self.pool.sync_backend.fetchall(sql, (), domain='audit')