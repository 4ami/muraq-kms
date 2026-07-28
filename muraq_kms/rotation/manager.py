import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone, timedelta

from muraq_kms.storage.pool import StoragePool
from muraq_kms.keys.repository import KeyRepository
from muraq_kms.keys.models import KeyVersionState, KeyVersionModel

from muraq_kms.rotation.repository import RotationRepository

from muraq_kms.crypto.primitives import encrypt_envelope

from muraq_kms.crypto.registry import MuraqKMSAlgorithms

from muraq_kms.audit.manager import AuditManager

logger = logging.getLogger("muraq_kms.rotation.manager")

class RotationManager:
    def __init__(self, rmk:bytes, ask:bytes, audit_manager:AuditManager, pool:Optional[StoragePool] = None, key_repo:Optional[KeyRepository] = None) -> None:
        self.pool = pool
        self.rmk = rmk
        self.ask = ask
        self.repo = RotationRepository(self.pool) if pool else None
        self.key_repo = key_repo or KeyRepository(self.pool)
        self.audit = audit_manager

    async def register_rotation_job_async(
        self, 
        logical_key_id: int, 
        interval_days: int = 90, 
        last_run: Optional[float] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Registers or updates a rotation job asynchronously via the manager.
        """
        if not self.repo:
            raise RuntimeError("RotationManager initialized without a valid StoragePool or RotationRepository.")
            
        return await self.repo.register_rotation_job_async(
            logical_key_id=logical_key_id,
            interval_days=interval_days,
            last_run=last_run
        )

    def register_rotation_job_sync(
        self, 
        logical_key_id: int, 
        interval_days: int = 90, 
        last_run: Optional[float] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Registers or updates a rotation job synchronously via the manager.
        """
        if not self.repo:
            raise RuntimeError("RotationManager initialized without a valid StoragePool or RotationRepository.")
            
        return self.repo.register_rotation_job_sync(
            logical_key_id=logical_key_id,
            interval_days=interval_days,
            last_run=last_run
        )
    
    async def process_scheduled_rotations(self) -> None:
        """
        Scans for overdue rotation jobs and executes physical key rollovers asynchronously.
        """
        overdue_jobs = await self.repo.get_overdue_jobs_async()
        if not overdue_jobs:
            return

        for job in overdue_jobs:
            logger.info(f"Background worker: Processing rotation for key '{job['key_name']}'")
            try:
                await self._rotate_key_async(job)
            except Exception as e:
                logger.error(f"FAIL CLOSED: Rollover failed for '{job['key_name']}': {e}")
                await self.audit.log_event_async(
                        action="KEY_ROTATE",
                        actor="system:rotation_daemon",
                        details={"key_name": job["key_name"], "error": str(e)},
                        status="FAILED",
                        ask=self.ask
                    )
                continue
    
    async def _rotate_key_async(self, job: Dict[str, Any]) -> str:
        logical_key_id = job["logical_key_id"]
        key_name = job["key_name"]
        interval_days = job["interval_days"]

        active_ver = await self.key_repo.get_active_version_for_logical_key_async(logical_key_id)
        if not active_ver:
            raise RuntimeError(f"Cannot rotate key '{key_name}': No active version found.")

        next_version = active_ver["version"] + 1
        new_kid = f"{key_name}:v{next_version}"
        algorithm = active_ver["algorithm"]
        
        spec = MuraqKMSAlgorithms.get_spec(algorithm)
        raw_material = spec.generator_func()

        now = datetime.now(tz=timezone.utc)
        next_run = now + timedelta(days=interval_days)

        new_version_model = KeyVersionModel(
            kid=new_kid,
            logical_key_id=logical_key_id,
            version=next_version,
            state=KeyVersionState.ACTIVE,
            algorithm=algorithm,
            raw_material=encrypt_envelope(raw_material, self.rmk).hex(),
            created_at=now,
            activated_at=now
        )

        await self.key_repo.update_key_state_async(
            kid=str(active_ver["kid"]), 
            next_state=KeyVersionState.DEPRECATED
        )

        await self.key_repo.save_key_version_async(new_version_model)

        await self.repo.update_job_schedule_async(
            job_id=job["job_id"],
            last_run=now.timestamp(),
            next_run=next_run.timestamp()
        )

        await self.audit.log_event_async(
                action="KEY_ROTATE",
                actor="system:rotation_daemon",
                details={
                    "logical_key_id": logical_key_id,
                    "old_kid": str(active_ver["kid"]),
                    "new_kid": new_kid,
                    "algorithm": algorithm
                },
                status="SUCCESS",
                ask=self.ask,
                timestamp=now
            )

        logger.info(f"Key rollover successful: '{key_name}' active version bumped to v{next_version} ({new_kid})")
        return new_kid

    def evaluate_and_rotate(self) -> List[str]:
        """
        Synchronous evaluation pass. Safe to call from CLI tools.
        """
        if not self.repo or not self.key_repo:
            raise RuntimeError("RotationManager initialized without a valid StoragePool or KeyRepository.")

        overdue_jobs = self.repo.get_overdue_jobs_sync()
        if not overdue_jobs:
            return []

        rotated_kids: List[str] = []

        for job in overdue_jobs:
            try:
                new_kid = self._rotate_key_sync(job)
                rotated_kids.append(new_kid)
            except Exception as e:
                self.audit.log_event_sync(
                        action="KEY_ROTATE",
                        actor="cli:rotation_worker",
                        details={"key_name": job["key_name"], "error": str(e)},
                        status="FAILED",
                        ask=self.ask
                    )
                logger.error(f"Sync rollover failed for key '{job['key_name']}': {e}")
                continue

        return rotated_kids
    
    def _rotate_key_sync(self, job: Dict[str, Any]) -> str:
        logical_key_id = job["logical_key_id"]
        key_name = job["key_name"]
        interval_days = job["interval_days"]

        active_ver = self.key_repo.get_active_version_for_logical_key_sync(logical_key_id)
        if not active_ver:
            raise RuntimeError(f"Cannot rotate key '{key_name}': No active version found.")

        next_version = active_ver["version"] + 1
        new_kid = f"{key_name}:v{next_version}"
        algorithm = active_ver["algorithm"]
        
        spec = MuraqKMSAlgorithms.get_spec(algorithm)
        raw_material = spec.generator_func()

        now = datetime.now(tz=timezone.utc)
        next_run = now + timedelta(days=interval_days)

        new_version_model = KeyVersionModel(
            kid=new_kid,
            logical_key_id=logical_key_id,
            version=next_version,
            state=KeyVersionState.ACTIVE,
            algorithm=algorithm,
            raw_material=encrypt_envelope(raw_material, self.rmk).hex(),
            created_at=now,
            activated_at=now
        )

        self.key_repo.update_key_state_sync(
            kid=str(active_ver["kid"]), 
            next_state=KeyVersionState.DEPRECATED
        )
        self.key_repo.save_key_version_sync(new_version_model)
        self.repo.update_job_schedule_sync(
            job_id=job["job_id"],
            last_run=now.timestamp(),
            next_run=next_run.timestamp()
        )

        self.audit.log_event_sync(
                action="KEY_ROTATE",
                actor="cli:rotation_worker",
                details={
                    "logical_key_id": logical_key_id,
                    "old_kid": str(active_ver["kid"]),
                    "new_kid": new_kid,
                    "algorithm": algorithm
                },
                status="SUCCESS",
                ask=self.ask,
                timestamp=now
            )

        logger.info(f"Sync key rollover successful: '{key_name}' active version bumped to v{next_version} ({new_kid})")
        return new_kid