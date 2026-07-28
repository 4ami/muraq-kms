from typing import Any, List, Optional
from datetime import datetime, timezone, timedelta
from muraq_kms.storage.pool import StoragePool

class RotationRepository:

    def __init__(self, pool:StoragePool) -> None:
        self.pool = pool
    
    async def get_overdue_jobs_async(self) -> List[dict[str, Any]]:
        """
        Fetches all policy jobs that have crossed their next_run window timestamp.
        """
        query = """
            SELECT r._id, r.logical_key_id, r.interval_days, l.name
            FROM rotation_jobs r
            JOIN logical_keys l ON r.logical_key_id = l._id
            WHERE r.next_run <= CURRENT_TIMESTAMP;
        """
        rows = await self.pool.async_backend.fetchall(query, ())
        if not rows:
            return []
            
        return [
            {
                "job_id": row[0],
                "logical_key_id": row[1],
                "interval_days": row[2],
                "key_name": row[3]
            }
            for row in rows
        ]
    
    def get_overdue_jobs_sync(self) -> List[dict[str, Any]]:
        """
        Fetches all policy jobs that have crossed their next_run window timestamp.
        """
        query = """
            SELECT r._id, r.logical_key_id, r.interval_days, l.name
            FROM rotation_jobs r
            JOIN logical_keys l ON r.logical_key_id = l._id
            WHERE r.next_run <= CURRENT_TIMESTAMP;
        """
        rows = self.pool.sync_backend.fetchall(query, ())
        if not rows:
            return []
            
        return [
            {
                "job_id": row[0],
                "logical_key_id": row[1],
                "interval_days": row[2],
                "key_name": row[3]
            }
            for row in rows
        ]

    async def update_job_schedule_async(self, job_id: int, last_run: float, next_run: float) -> None:
        """
        Updates the execution timestamps for a rotation job asynchronously.
        """
        query = "UPDATE rotation_jobs SET last_run = ?, next_run = ? WHERE _id = ?;"
        await self.pool.async_backend.execute(query, (last_run, next_run, job_id))

    def update_job_schedule_sync(self, job_id: int, last_run: float, next_run: float) -> None:
        """
        Updates the execution timestamps for a rotation job synchronously.
        """
        query = "UPDATE rotation_jobs SET last_run = ?, next_run = ? WHERE _id = ?;"
        self.pool.sync_backend.execute(query, (last_run, next_run, job_id))

    async def register_rotation_job_async(
        self, 
        logical_key_id: int, 
        interval_days: int = 90, 
        last_run: Optional[float] = None
    ) -> Optional[dict[str, Any]]:
        """
        Registers or updates a rotation job for a key. Calculates initial next_run timestamp.
        """
        now = datetime.now(tz=timezone.utc)
        next_run = (now + timedelta(days=interval_days)).timestamp()
        
        query = """
            INSERT INTO rotation_jobs (logical_key_id, interval_days, last_run, next_run)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(logical_key_id) DO UPDATE SET
                interval_days = excluded.interval_days,
                next_run = excluded.next_run
            RETURNING interval_days, next_run;
        """
        row = None
        async with self.pool.async_backend.transaction(domain='keys') as conn:
            cursor = conn.execute(query, (logical_key_id, interval_days, last_run, next_run))
            row = cursor.fetchone()

        return {"interval_days": row[0], "next_run": row[1]}

    def register_rotation_job_sync(
        self, 
        logical_key_id: int, 
        interval_days: int = 90, 
        last_run: Optional[float] = None
    ) -> Optional[dict[str, Any]]:
        """
        Registers or updates a rotation job for a key synchronously.
        """
        now = datetime.now(tz=timezone.utc)
        next_run = (now + timedelta(days=interval_days)).timestamp()
        
        query = """
            INSERT INTO rotation_jobs (logical_key_id, interval_days, last_run, next_run)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(logical_key_id) DO UPDATE SET
                interval_days = excluded.interval_days,
                next_run = excluded.next_run
            RETURNING interval_days, next_run;
        """
        row = None
        with self.pool.sync_backend.transaction(domain='keys') as conn:
            cursor = conn.execute(query, (logical_key_id, interval_days, last_run, next_run))
            row = cursor.fetchone()

        return {"interval_days": row[0], "next_run": row[1]}