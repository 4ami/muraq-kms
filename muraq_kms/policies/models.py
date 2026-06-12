from pydantic import BaseModel, Field, field_validator
from typing import Dict

class KeyAccessPolicy(BaseModel):
    """
    Validates configuration rules governing access modes to raw key material
    as defined under SRS Section 18 (FR-14).
    """
    export:bool = Field(
    False,
    description="Allows permanent raw material extraction.")

    borrow:bool = Field(
    False,
    description="Allows temporary scoped leasing of raw material.")

    borrow_ttl_seconds:int = Field(
    30, 
    description="Enforced maximum lifespan of an ephemeral key lease.")

    @field_validator("borrow_ttl_seconds")
    @classmethod
    def validate_ttl_bounds(cls, value:int) -> int:
        if value <= 0 or value > 3600:
            raise ValueError("Borrow TTL must remain bounded between 1 and 3600 seconds.")
        return value


class PolicyManifest(BaseModel):
    """
    Maps logical key identifiers to their explicit enforcement policies.
    """
    policies:Dict[str, KeyAccessPolicy] = Field(default_factory=dict)