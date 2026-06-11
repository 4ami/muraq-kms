from dataclasses import dataclass, field
from typing import List

@dataclass(frozen=True)
class Issue:
    asset: str
    message: str
    is_critical: bool
    can_fix: str

@dataclass
class DiagnosticReport:
    issues: List[Issue] = field(default_factory=list)

    @property
    def has_critical(self) -> bool:
        return any(i.is_critical for i in self.issues)

    @property
    def is_healthy(self) -> bool:
        return len(self.issues) == 0