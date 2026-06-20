import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def generate_secure_bytes(length:int = 32) -> bytes:
    return os.urandom(length)

def encrypt_envelope(plaintext:bytes, wrapping_key:bytes) -> bytes:
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