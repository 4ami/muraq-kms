import time
import hmac
import hashlib
from dataclasses import dataclass

from muraq_kms.storage import StorageConfig, MigrationRunner, SQLiteStorage

@dataclass(frozen=True)
class ThrottleStatus:
    is_locked: bool
    remaining_seconds: float
    was_tampered: bool
    remaining_attempts: int

class ThrottlingEngine:
    """
    Encapsulates ACID-compliant brute-force defense, tamper detection, 
    and self-healing state transitions for the KMS appliances.
    """
    MAX_ATTEMPTS = 5
    LOCKOUT_DURATION = 600
    TAMPER_LOCKOUT_DURATION = 1800

    def __init__(self, config:StorageConfig, deployment_id:str) -> None:
        self.db_path = config.state_db_path
        self.base_dir = config.base_dir
        self._sqlite = SQLiteStorage(config)
        entropy = f"{self.base_dir.resolve()}::{deployment_id}".encode("utf-8")
        self._integrity_key = hashlib.sha256(entropy).digest()
    
    def _init_db(self) -> None:
        runner = MigrationRunner(self.db_path, domain="state_db")
        try:
            runner.upgrade()
        finally:
            runner.close()
    
    def _compute_signature(self, attemtps:int, locked_until:float) -> str:
        canonical = f"{attemtps}|{locked_until}"
        return hmac.new(self._integrity_key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    
    def _write_state(self, attempts:int, locked_until:float) -> None:
        self._init_db()
        sig = self._compute_signature(attempts, locked_until)

        with self._sqlite.transaction(domain="state") as conn:
            conn.execute("""
            INSERT INTO throttling_state (id, failed_attempts, locked_until_epoch, tamper_signature)
            VALUES (1, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
            failed_attempts=excluded.failed_attempts,
            locked_until_epoch=excluded.locked_until_epoch,
            tamper_signature=excluded.tamper_signature
            """, (attempts, locked_until, sig))
            conn.commit()
    
    def check_status(self) -> ThrottleStatus:
        ctime = time.time()

        if not self.db_path.exists():
            return ThrottleStatus(
                is_locked=True, remaining_attempts=0,
                was_tampered=True, remaining_seconds=self.TAMPER_LOCKOUT_DURATION
            )
        
        try:
            self._init_db()
            with self._sqlite.transaction(domain="state") as conn:
                row = conn.execute("SELECT failed_attempts, locked_until_epoch, tamper_signature FROM throttling_state WHERE id=1").fetchone()
            
            if not row:
                return ThrottleStatus(
                    is_locked=True,
                    remaining_seconds=self.TAMPER_LOCKOUT_DURATION,
                    was_tampered=True,
                    remaining_attempts=0
                )
            
            attempts, locked_until, sig = row

            if sig == "INITIALIZED":
                self.record_success()
                return ThrottleStatus(
                    is_locked=False, remaining_seconds=0.0,
                    was_tampered=False, remaining_attempts=self.MAX_ATTEMPTS
                )

            expected_sig = self._compute_signature(attempts, locked_until)
            if not hmac.compare_digest(sig, expected_sig):
                return ThrottleStatus(
                    is_locked=True,
                    remaining_seconds=self.TAMPER_LOCKOUT_DURATION,
                    was_tampered=True,
                    remaining_attempts=0
                )
            
            if ctime < locked_until:
                return ThrottleStatus(
                    is_locked=True,
                    remaining_seconds=locked_until - ctime,
                    was_tampered=False,
                    remaining_attempts=0
                )
            
            if locked_until > 0.0 and ctime >= locked_until:
                self.record_success()
                attempts = 0
            
            return ThrottleStatus(
                is_locked=False,
                remaining_seconds=0.0,
                was_tampered=False,
                remaining_attempts=self.MAX_ATTEMPTS - attempts
            )
        except Exception:
            return ThrottleStatus(
                is_locked=True,
                remaining_seconds=self.TAMPER_LOCKOUT_DURATION,
                was_tampered=True,
                remaining_attempts=0
            )
    
    def enforce_tamper_lockout(self) -> None:
        forced_lockout = time.time() + self.TAMPER_LOCKOUT_DURATION
        self._write_state(
            attempts=self.MAX_ATTEMPTS,
            locked_until=forced_lockout
        )
    
    def record_success(self) -> None:
        self._write_state(attempts=0, locked_until=0.0)
    
    def record_failure(self) -> ThrottleStatus:
        try:
            self._init_db()
            with self._sqlite.transaction(domain="state") as conn:
                row = conn.execute("SELECT failed_attempts FROM throttling_state WHERE id=1").fetchone()
            cattempts = row[0] if row else 0
        except Exception:
            cattempts = 0
        
        new_attempts = cattempts + 1

        if new_attempts >= self.MAX_ATTEMPTS:
            locked_until = time.time() + self.LOCKOUT_DURATION
            self._write_state(attempts=new_attempts, locked_until=locked_until)
            return ThrottleStatus(
                is_locked=True,
                remaining_seconds=self.LOCKOUT_DURATION,
                was_tampered=False,
                remaining_attempts=0
            )
        else:
            self._write_state(attempts=new_attempts, locked_until=0.0)
            return ThrottleStatus(
                is_locked=False,
                remaining_seconds=0,
                was_tampered=False,
                remaining_attempts=self.MAX_ATTEMPTS - new_attempts
            )