import pytest
import time
from muraq_kms.policies.models import PolicyManifest, KeyAccessPolicy
from muraq_kms.policies.evaluator import PolicyEvaluator
from muraq_kms.policies.lease import borrow_key_context
from muraq_kms.policies.policy_errors import PolicyDenialError, LeaseExpiredError

def test_policy_evaluator_fails_closed_by_default():
    evaluator = PolicyEvaluator()
    
    with pytest.raises(PolicyDenialError) as exc:
        evaluator.authorize_borrow("UNKNOWN_KEY")
    assert "No access policy registered" in str(exc.value)

def test_policy_evaluator_authorizes_valid_configurations():
    manifest = PolicyManifest(policies={
        "JWT_SIGNING_KEY": KeyAccessPolicy(borrow=True, borrow_ttl_seconds=15)
    })
    evaluator = PolicyEvaluator(manifest)
    
    policy = evaluator.authorize_borrow("JWT_SIGNING_KEY")
    assert policy.borrow is True
    assert policy.borrow_ttl_seconds == 15

def test_ephemeral_lease_context_zeroizes_on_exit():
    secret_bytes = b"super-secret-raw-key-material-32"
    
    with borrow_key_context("JWT_KEY", secret_bytes, ttl_seconds=5) as lease:
        assert lease.key_material == secret_bytes
        target_buffer = lease._buffer
        assert bytes(target_buffer) == secret_bytes

    assert lease._invalidated is True
    assert bytes(target_buffer) == b"\x00" * len(secret_bytes)


def test_ephemeral_lease_enforces_ttl_expiration():
    secret_bytes = b"short-lived-token"
    
    with borrow_key_context("TIMEOUT_KEY", secret_bytes, ttl_seconds=1) as lease:
        lease._expires_at = time.time() - 1 
        
        with pytest.raises(LeaseExpiredError):
            _ = lease.key_material