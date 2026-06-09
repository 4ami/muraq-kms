import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class StorageConfig:
    base_dir: Path

    @property
    def db_path(self) -> Path:
        return self.base_dir / "keys.db"
    
    @property
    def audit_db_path(self) -> Path:
        return self.base_dir / "audit" / "audit.db"

    @property
    def recovery_db_path(self) -> Path:
        return self.base_dir / "recovery" / "recovery.db"

    @classmethod
    def from_env(cls) -> "StorageConfig":
        return cls(Path(os.environ.get("MKMS_DATA_DIR", "/var/lib/muraq/kms")))

    def ensure_layout(self) -> None:
        self.base_dir.mkdir(parents=True, exist_ok=True)
        for subdir in ("audit", "recovery", "backups"):
            (self.base_dir / subdir).mkdir(exist_ok=True)
