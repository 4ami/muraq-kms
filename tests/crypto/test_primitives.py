import pytest

from muraq_kms.crypto.primitives import (
    asymmetric_encrypt,
    asymmetric_decrypt
)
from muraq_kms.crypto.registry import MuraqKMSAlgorithms, AlgorithmType

# ── asymmetric primitive tests ────────────────────────────────────────────────

def test_asymmetric_lifecycle_convergence():
    """Verify that small payload memory messages can be wrapped and unwrapped using private keys."""
    spec = MuraqKMSAlgorithms.get_spec("RS256")
    private_pem = spec.generator_func()
    
    payload = b"muraq-kms-secret-payload-token"
    
    ciphertext = asymmetric_encrypt(payload, private_pem)
    assert ciphertext != payload
    assert len(ciphertext) > 4
    
    decrypted = asymmetric_decrypt(ciphertext, private_pem)
    assert decrypted == payload


def test_asymmetric_decrypt_rejects_corrupted_wire_prefixes():
    """Ensure invalid byte structures or truncated streams fail early during asymmetric decoding."""
    spec = MuraqKMSAlgorithms.get_spec("RS256")
    private_pem = spec.generator_func()
    
    with pytest.raises(ValueError, match="too short"):
        asymmetric_decrypt(b"\x00\x00", private_pem)
        
    with pytest.raises(ValueError, match="exceeds available bytes"):
        asymmetric_decrypt(b"\x00\x00\x00\x64\xaa\xbb", private_pem)

# ── polymorphic registry tests ────────────────────────────────────────────────

def test_registry_contains_all_core_algorithms():
    """Verify registry specifications for both symmetric and asymmetric algorithms."""
    for algo_code in ["XCHACHA20", "AES256", "RS256", "RS512"]:
        spec = MuraqKMSAlgorithms.get_spec(algo_code)
        assert spec.name is not None
        assert isinstance(spec.type, AlgorithmType)


def test_registry_raises_on_unknown_identifiers():
    """Ensure accessing an invalid algorithm string throws a ValueError constraint error."""
    with pytest.raises(ValueError, match="Unsupported algorithm"):
        MuraqKMSAlgorithms.get_spec("ROT13_UNSAFE")