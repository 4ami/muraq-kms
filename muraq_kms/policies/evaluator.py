from typing import Dict, Any, Optional

from muraq_kms.policies.models import PolicyManifest, KeyAccessPolicy
from muraq_kms.policies.policy_error import PolicyDenialError

class PolicyEvaluator:
    def __init__(self, manifest: Optional[PolicyManifest] = None) -> None:
        self.manifest = manifest or PolicyManifest()

    def authorize_borrow(self, key_id:str) -> KeyAccessPolicy:
        """
        Evaluates authorization context against active resource records.
        Implements a strict fail-closed boundary pattern.
        """
        if key_id not in self.manifest.policies:
            raise PolicyDenialError(f"Access Denied: No access policy registered for key '{key_id}'.")
        
        policy = self.manifest.policies[key_id]

        if not policy.borrow:
            raise PolicyDenialError(f"Access Denied: Ephemeral borrowing is explicitly disabled for key '{key_id}'.")
        
        return policy