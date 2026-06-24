
"""
muraq_kms/crypto/primitives.py
 
Low-level cryptographic building blocks.
 
Symmetric helpers (encrypt_envelope / decrypt_envelope) use AES-256-GCM with a
fresh 12-byte random nonce prepended to every ciphertext.
 
Asymmetric helpers (asymmetric_encrypt / asymmetric_decrypt) implement a hybrid
envelope: a fresh 32-byte ephemeral DEK is AES-GCM-encrypted around the
plaintext, then the DEK itself is RSA-OAEP wrapped with the public key derived
from the supplied private PEM.  The wire format is:
 
    ┌─────────────────────────────────────────────┐
    │ 4 B  wrapped_dek_len   uint32 big-endian    │
    │ N B  wrapped_dek       RSA-OAEP(DEK)        │
    │ K B  encrypted_payload AES-GCM(plaintext)   │
    └─────────────────────────────────────────────┘
 
These functions are intentionally in-memory only.  For large files use the
streaming API in muraq_kms.crypto.streaming instead.
"""
from __future__ import annotations
import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# ── struct helper ─────────────────────────────────────────────────────────────

_UINT32 = struct.Struct(">I")

# ── symmetric primitives ──────────────────────────────────────────────────────

def generate_secure_bytes(length:int = 32) -> bytes:
    return os.urandom(length)

def encrypt_envelope(plaintext:bytes, wrapping_key:bytes) -> bytes:
    """
    AES-256-GCM encrypt *plaintext* with *wrapping_key*.
 
    Output layout: 12-byte nonce ‖ ciphertext ‖ 16-byte GCM tag.
    """
    if len(wrapping_key) != 32:
        raise ValueError("256-bit (32-bytes) key size is required.")
    
    aesgcm = AESGCM(wrapping_key)
    nonce = os.urandom(12)

    ciphertext = aesgcm.encrypt(
        nonce=nonce,
        data=plaintext,
        associated_data=None
    )

    return nonce + ciphertext

def decrypt_envelope(ciphertext:bytes, wrapping_key:bytes) -> bytes:
    """
    AES-256-GCM decrypt *ciphertext* produced by encrypt_envelope.
 
    Expects: 12-byte nonce ‖ ciphertext ‖ 16-byte GCM tag.
    """
    if len(wrapping_key) != 32:
        raise ValueError("256-bit (32-bytes) key size is required.")
    
    if len(ciphertext) < 28:
        raise ValueError("Ciphertext format is corrupted/incomplete.")
    
    nonce = ciphertext[:12]
    cipherdata = ciphertext[12:]

    aesgcm = AESGCM(wrapping_key)

    return aesgcm.decrypt(nonce=nonce, data=cipherdata, associated_data=None)

def split_root_secret(raw_drs:bytes, deployment_salt:bytes) -> tuple[bytes, bytes]:
    if len(deployment_salt) < 16:
        raise ValueError("Deployment salt must be a high-entropy.")

    rmk_hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=deployment_salt + b"_mkms_recovery",
        info=b"muraq_kms_recevory_vault_isolation_key"
    )

    rmk = rmk_hkdf.derive(raw_drs)

    audit_hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=deployment_salt + b"_mkms_audit",
        info=b"muraq_kms_audit_ledger_hmac_signing_key"
    )

    ask = audit_hkdf.derive(raw_drs)

    return rmk, ask

def mask(value: str, visible_prefix:int = 4, mask_char: str = "*") -> str:
    """
    Transforms a secret string into a safe display format.
    Example: 'my-super-secret-key-material' -> '****************erial'
    """
    if not value: return ""

    if len(value) <= visible_prefix:
        return mask_char * len(value)
    
    return f"{value[:visible_prefix]}{mask_char * (len(value) - visible_prefix)}"

# ── asymmetric hybrid primitives ──────────────────────────────────────────────

def asymmetric_encrypt(msg:bytes, private_pem:bytes) -> bytes:
    """
    Hybrid RSA+AES-GCM encryption for *small* in-memory payloads.
 
    A fresh 32-byte ephemeral DEK is generated, used to AES-GCM encrypt
    *msg*, then RSA-OAEP wrapped with the public key extracted from
    *private_pem*.
 
    Wire format:
        4 B  wrapped_dek_len  (uint32 big-endian)
        N B  wrapped_dek      (RSA-OAEP ciphertext — key-size dependent)
        K B  encrypted_payload (nonce ‖ AES-GCM ciphertext ‖ tag)
 
    Args:
        msg:         Plaintext bytes to encrypt.
        private_pem: RSA private key in unencrypted PEM/PKCS8 format.
                     The *public* key is derived from it for DEK wrapping,
                     so the holder of the private key can always decrypt.
 
    Returns:
        Raw ciphertext bytes in the wire format described above.
 
    Raises:
        TypeError   – if the key type does not support RSA-OAEP encryption.
        ValueError  – if the PEM cannot be parsed.
    """
    ephemeral_dek = generate_secure_bytes()

    try:
        encrypted_payload = encrypt_envelope(msg, ephemeral_dek)
        wrapped_dek = _rsa_oaep_wrap(private_pem, ephemeral_dek)
        return _UINT32.pack(len(wrapped_dek)) + wrapped_dek + encrypted_payload
    finally:
        ephemeral_dek = b"\x00" * len(ephemeral_dek)

def asymmetric_decrypt(ciphertext:bytes, private_pem:bytes) -> bytes:
    """
    Hybrid RSA+AES-GCM decryption — inverse of asymmetric_encrypt.
 
    Parses the wire format, RSA-OAEP unwraps the DEK with *private_pem*,
    then AES-GCM decrypts the payload.
 
    Args:
        ciphertext:  Bytes produced by asymmetric_encrypt.
        private_pem: RSA private key in unencrypted PEM/PKCS8 format.
 
    Returns:
        Original plaintext bytes.
 
    Raises:
        ValueError  – on a malformed or truncated ciphertext stream.
        TypeError   – if the key type does not support RSA-OAEP decryption.
    """
    if len(ciphertext) < 4:
        raise ValueError("Malformed ciphertext: too short to contain the DEK length prefix.")
    
    (dek_len,) =_UINT32.unpack(ciphertext[:4])

    if len(ciphertext) < (4 + dek_len):
        raise ValueError(
            f"Malformed ciphertext: declared DEK length ({dek_len} B) "
            "exceeds available bytes."
        )
    
    wrapped_dek = ciphertext[4:4 + dek_len]
    encrypted_payload = ciphertext[4 + dek_len: ]

    if not encrypted_payload:
        raise ValueError("Malformed ciphertext: no encrypted payload found after the DEK block.")
    
    ephemeral_dek = _rsa_oaep_unwrap(private_pem, wrapped_dek)

    try:
        return decrypt_envelope(encrypted_payload, ephemeral_dek)
    finally:
        ephemeral_dek = b"\x00" * len(ephemeral_dek)

# ── internal RSA-OAEP helpers ────────────────────────────────────────────────
#
# These are private to this module.  streaming.py has its own copies so that
# neither module imports from the other (avoids a circular dependency).
 
 
def _rsa_oaep_wrap(private_pem: bytes, dek: bytes) -> bytes:
    """
    RSA-OAEP encrypt *dek* with the public key extracted from *private_pem*.
 
    Using the public key for wrapping means any holder of the private key
    can unwrap — this is the standard hybrid-encryption direction.
    """
    private_key = serialization.load_pem_private_key(private_pem, password=None)
    public_key = private_key.public_key()
 
    if not hasattr(public_key, "encrypt"):
        raise TypeError(
            "The supplied key does not support RSA-OAEP encryption. "
            "Only RSA keys are accepted by asymmetric_encrypt."
        )
 
    return public_key.encrypt(
        dek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
 
 
def _rsa_oaep_unwrap(private_pem: bytes, wrapped_dek: bytes) -> bytes:
    """RSA-OAEP decrypt *wrapped_dek* using *private_pem*."""
    private_key = serialization.load_pem_private_key(private_pem, password=None)
 
    if not hasattr(private_key, "decrypt"):
        raise TypeError(
            "The supplied key does not support RSA-OAEP decryption. "
            "Only RSA private keys are accepted by asymmetric_decrypt."
        )
 
    return private_key.decrypt(
        wrapped_dek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )