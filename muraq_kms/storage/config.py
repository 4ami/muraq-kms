import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class StorageConfig:
    base_dir: Path

    def __post_init__(self) -> None:
        """
        Enforces a structural sandbox boundary. 
        Ensures that every base_dir automatically appends and points into an isolated 
        '.muraq-kms' subdirectory to prevent root or working directory wiping.
        """
        suffix = ".muraq-kms"

        resolved_path = self.base_dir.absolute().resolve()

        if resolved_path.name != suffix:
            safe_path = resolved_path / suffix
        else:
            safe_path = resolved_path
        
        object.__setattr__(self, "base_dir", safe_path)

    @property
    def db_path(self) -> Path:
        return self.base_dir / "keys.db"

    @property
    def state_db_path(self) -> Path:
        return self.base_dir / "state.db"
    
    @property
    def audit_db_path(self) -> Path:
        return self.base_dir / "audit" / "audit.db"

    @property
    def recovery_db_path(self) -> Path:
        return self.base_dir / "recovery" / "recovery.db"

    @classmethod
    def from_env(cls) -> "StorageConfig":
        return cls(Path(os.environ.get("MKMS_DATA_DIR", str(Path.home() / ".muraq-kms"))))

    def ensure_layout(self) -> None:
        self.base_dir.mkdir(parents=True, exist_ok=True)
        for subdir in ("audit", "recovery", "backups"):
            (self.base_dir / subdir).mkdir(parents=True, exist_ok=True)
