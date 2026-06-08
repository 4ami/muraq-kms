import pytest
import os
from crypto.primitives import encrypt_envelope, decrypt_envelope, generate_secure_bytes
from cryptography.exceptions import InvalidTag

def test_envelope_lifecycle_convergence(valid_key_wrapping_key):
    payload = b"sensitive_deployment_root_secret_bytes"
    ciphertext = encrypt_envelope(payload, valid_key_wrapping_key)
    
    assert ciphertext != payload
    assert len(ciphertext) > len(payload)
    
    decrypted = decrypt_envelope(ciphertext, valid_key_wrapping_key)
    assert decrypted == payload

def test_envelope_fails_on_unauthorized_key():
    payload = b"classified_data"
    key_owner = generate_secure_bytes(32)
    key_attacker = generate_secure_bytes(32)
    
    ciphertext = encrypt_envelope(payload, key_owner)
    
    with pytest.raises(InvalidTag):
        decrypt_envelope(ciphertext, key_attacker)

def test_envelope_detects_malicious_tampering(valid_key_wrapping_key):
    payload = b"immutable_ledger_record"
    ciphertext = encrypt_envelope(payload, valid_key_wrapping_key)
    
    tampered_bytes = bytearray(ciphertext)
    tampered_bytes[-1] ^= 0x01
    
    with pytest.raises(InvalidTag):
        decrypt_envelope(bytes(tampered_bytes), valid_key_wrapping_key)

def test_envelope_checks_key_length_constraints():
    bad_key = b"short-key"
    with pytest.raises(ValueError, match="256-bit .* required"):
        encrypt_envelope(b"data", bad_key)
        
    with pytest.raises(ValueError, match="256-bit .* required"):
        decrypt_envelope(b"data-packet-buffer-padding-space", bad_key)

def test_envelope_reconciles_truncated_payloads(valid_key_wrapping_key):
    with pytest.raises(ValueError, match="Ciphertext format is corrupted"):
        decrypt_envelope(b"too-short-to-hold-nonce-tag", valid_key_wrapping_key)