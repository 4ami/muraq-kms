from pydantic import BaseModel, Field, field_validator
from typing import Optional
from datetime import datetime, timezone
from enum import Enum

from muraq_kms.crypto.registry import MuraqKMSAlgorithms

class LogicalKeyModel(BaseModel):
    id:Optional[int] = Field(None,
    alias="_id")

    name:str = Field(...,
    description="Unique alias identifier.")

    description:Optional[str] = Field(None)

    exportable:int = Field(0,
    description="Boolean proxy integer: 0 or 1.")
    
    borrowable:int = Field(0,
    description="Boolean proxy integer: 0 or 1.")

    borrow_ttl_seconds:Optional[int] = Field(30)

    created_at:datetime = Field(..., default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("exportable", "borrowable")
    @classmethod
    def validate_bool(cls, val:int) -> int:
        if val not in (0, 1):
            raise ValueError("Boolean properties must be exactly represented as 0 or 1 integers.")
        return val

class KeyVersionState(str, Enum):
    ACTIVE = 'active'
    DEPRECATED = 'deprecated'
    REVOKED = 'revoked'
    ARCHIVED = 'archived'
    DESTROYED = 'destroyed'
    ELIGIBLE_FOR_DESTROY = 'eligible_for_destroy'

class KeyVersionModel(BaseModel):
    kid:str = Field(...,
    description="Unique text primary key identifier.")

    logical_key_id:int = Field(...)

    version:int = Field(...)

    state:KeyVersionState = Field(...)

    algorithm:str = Field(...)

    raw_material:str = Field(...)

    created_at:datetime = Field(..., default_factory=lambda: datetime.now(timezone.utc))

    activated_at:Optional[datetime] = Field(None)

    revoked_at:Optional[datetime] = Field(None)

    archived_at:Optional[datetime] = Field(None)

    destroyed_at:Optional[datetime] = Field(None)

    @field_validator("algorithm")
    @classmethod
    def validate_supported_cryptography(cls, value: str) -> str:
        upper_val = value.upper().strip()
        if upper_val not in MuraqKMSAlgorithms.CODES:
            raise ValueError(
                f"Invalid primitive choice '{value}'. "
                f"Must accurately reflect one of: {MuraqKMSAlgorithms.CODES}"
            )
        return upper_val


class KeyDependencyStatus(str, Enum):
    COUPLED = 'coupled'
    MIGRATING = 'migrating'
    ORPHAN = 'orphan'
    QUARANTINED = 'quarantined'

class KeyDependencyModel(BaseModel):
    id:Optional[str] = Field(None,
    alias="_id")

    ciphertext_id:str = Field(...)

    ref_kid:str = Field(...)

    status:KeyDependencyStatus = Field(...)

    registered_at:datetime = Field(..., default_factory=lambda: datetime.now(timezone.utc))