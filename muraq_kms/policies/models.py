from pydantic import BaseModel, Field, model_validator
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
    0, 
    description="Enforced maximum lifespan of an ephemeral key lease.")

    @model_validator(mode="after")
    def validate_policy_interdependence(self) -> "KeyAccessPolicy":
        if not self.borrow:
            if self.borrow_ttl_seconds != 0:
                raise ValueError("Borrow TTL must be 0 if borrow mode is disabled.")
            return self

        if self.borrow_ttl_seconds <= 0 or self.borrow_ttl_seconds > 3600:
            raise ValueError("Borrow TTL must remain bounded between 1 and 3600 seconds when borrow is enabled.")         
        return self

class PolicyManifest(BaseModel):
    """
    Maps logical key identifiers to their explicit enforcement policies.
    """
    policies:Dict[str, KeyAccessPolicy] = Field(default_factory=dict)