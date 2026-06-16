from datetime import datetime, timezone
from pydantic import BaseModel, Field, field_validator, ConfigDict
from typing import Optional

class AuditEntry(BaseModel):
    id: Optional[int] = Field(
    default=None, 
    description="Primary incremental identifier from database layer.")

    timestamp: datetime = Field(
    default_factory=lambda: datetime.now(timezone.utc), 
    description="Unix timestamp of the operation occurrence.")

    action: str = Field(..., 
    description="The operation executed (e.g., 'kms:borrow', 'kms:create', 'policy:denial').")

    actor: str = Field(..., 
    description="The identifier of the initiating entity or subsystem.")

    details: str = Field(..., 
    description="JSON serialized string of operation metadata/resource contexts.")

    status: str = Field(..., 
    description="Must map to database constraint check: SUCCESS, DENIED, or FAILED.")

    previous_hash: str = Field(..., 
    description="Hexadecimal SHA-256 string hash of the parent entry block.")

    hash: str = Field(default="", 
    description="Hexadecimal SHA-256 hash containing the entry signature.")

    @field_validator("status")
    @classmethod
    def validate_db_status_constraint(cls, value: str) -> str:
        upper_val = value.upper()
        if upper_val not in {"SUCCESS", "DENIED", "FAILED"}:
            raise ValueError("Status must exactly match database constraint: 'SUCCESS', 'DENIED', or 'FAILED'.")
        return upper_val
    
    model_config = ConfigDict(populate_by_name=True)


