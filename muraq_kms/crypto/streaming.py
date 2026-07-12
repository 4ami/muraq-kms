"""
muraq_kms/crypto/streaming.py
 
Chunk-based streaming encryption/decryption for arbitrarily large files.
Memory footprint is bounded to CHUNK_SIZE regardless of input size.
 
File format (written by encrypt_file_stream):
 
    ┌─────────────────────────────────────────────┐
    │ 4 B  magic          b"MKMS"                 │
    │ 1 B  version        0x01                    │
    │ 2 B  algo_name_len  uint16 big-endian       │
    │ N B  algo_name      UTF-8 string            │
    │ 4 B  chunk_size     uint32 big-endian       │
    │ 4 B  chunk_count    uint32 big-endian       │
    │ 4 B  wrapped_dek_len  uint32 BE (0 = sym)   │
    │ M B  wrapped_dek    present only if asym    │
    │32 B  header_hmac    HMAC-SHA256 (see below) │
    ├─────────────────────────────────────────────┤
    │ per chunk (repeated chunk_count times):     │
    │   4 B  ciphertext_len  uint32 big-endian    │
    │   K B  ciphertext      nonce‖ciphertext‖tag │
    └─────────────────────────────────────────────┘
 
header_hmac is HMAC-SHA256 over every byte written before it, keyed with
the first 32 bytes of the raw symmetric key (or ephemeral DEK for asym).
This prevents header field tampering (chunk_size, chunk_count, algo swap).
 
Each chunk ciphertext is produced by encrypt_envelope(), which prepends a
fresh 12-byte random nonce and appends a 16-byte AES-GCM auth tag, so
every chunk is independently authenticated.
"""

from __future__ import annotations
 
import hmac
import hashlib
import io
import struct
from pathlib import Path
from typing import Callable, Generator, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
 
from muraq_kms.crypto.primitives import (
    decrypt_envelope,
    encrypt_envelope,
    generate_secure_bytes,
)

# ── constants ────────────────────────────────────────────────────────────────
 
MAGIC = b"MKMS"
VERSION = 0x01
DEFAULT_CHUNK_SIZE = 64 * 1024  # 64 KiB
 
_UINT8 = struct.Struct(">B")
_UINT16 = struct.Struct(">H")
_UINT32 = struct.Struct(">I")
 
 
# ── internal helpers ─────────────────────────────────────────────────────────

def _hmac_header(raw_key_or_dek: bytes, header_bytes: bytes) -> bytes:
    """HMAC-SHA256 over header_bytes, keyed with the first 32 bytes of the key."""
    mac_key = raw_key_or_dek[:32]
    return hmac.new(mac_key, header_bytes, hashlib.sha256).digest()

def _iter_chunks(
    src: io.RawIOBase | io.BufferedIOBase,
    chunk_size: int,
) -> Generator[bytes, None, None]:
    """Yield successive fixed-size byte chunks from a binary stream."""
    while True:
        block = src.read(chunk_size)
        if not block:
            break
        yield block

def _build_header(
    algo_name: str,
    chunk_size: int,
    chunk_count: int,
    wrapped_dek: bytes,
    mac_key: bytes,
) -> bytes:
    """
    Serialise the file header and append the HMAC over it.
    Returns the complete header as a single bytes object.
    """
    algo_bytes = algo_name.encode("utf-8")
    algo_len = len(algo_bytes)
 
    buf = (
        MAGIC
        + _UINT8.pack(VERSION)
        + _UINT16.pack(algo_len)
        + algo_bytes
        + _UINT32.pack(chunk_size)
        + _UINT32.pack(chunk_count)
        + _UINT32.pack(len(wrapped_dek))
        + wrapped_dek
    )
 
    return buf + _hmac_header(mac_key, buf)

def _parse_header(
    src: io.RawIOBase | io.BufferedIOBase,
) -> tuple[str, int, int, bytes, bytes]:
    """
    Read and validate the file header from an open binary stream.
 
    Returns:
        algo_name    – algorithm name string
        chunk_size   – plaintext chunk size used during encryption
        chunk_count  – number of ciphertext chunks that follow
        wrapped_dek  – RSA-wrapped DEK bytes (empty for symmetric)
        stored_hmac  – the 32-byte HMAC stored in the file (caller verifies)
 
    Raises:
        ValueError on magic/version mismatch or truncated header.
    """
    def _read_exact(n: int) -> bytes:
        data = src.read(n)
        if len(data) != n:
            raise ValueError(
                f"Truncated header: expected {n} bytes, got {len(data)}."
            )
        return data
 
    magic = _read_exact(4)
    if magic != MAGIC:
        raise ValueError(
            f"Invalid file magic. Got {magic!r}, expected {MAGIC!r}. "
            "This is not a MKMS-encrypted file."
        )
 
    (version,) = _UINT8.unpack(_read_exact(1))
    if version != VERSION:
        raise ValueError(
            f"Unsupported format version 0x{version:02X}. "
            f"This build only supports version 0x{VERSION:02X}."
        )
 
    (algo_len,) = _UINT16.unpack(_read_exact(2))
    algo_name = _read_exact(algo_len).decode("utf-8")
 
    (chunk_size,) = _UINT32.unpack(_read_exact(4))
    (chunk_count,) = _UINT32.unpack(_read_exact(4))
 
    (dek_len,) = _UINT32.unpack(_read_exact(4))
    wrapped_dek = _read_exact(dek_len) if dek_len else b""
 
    stored_hmac = _read_exact(32)
 
    return algo_name, chunk_size, chunk_count, wrapped_dek, stored_hmac


# ── public streaming API ─────────────────────────────────────────────────────

def generate_file_cid(path:Path) -> str:
    """
    Generate a unique ciphertext dependency identifier by parsing and 
    hashing the file's exact structural header bytes.
    """
    with open(path, 'rb') as src:
        st = src.tell()
        _parse_header(src)
        end = src.tell()
        src.seek(st)
        raw = src.read(end - st)
    return f"FILE_CID:{hashlib.sha256(raw).hexdigest()}"

def encrypt_file_stream(
    src_path: Path,
    dst_path: Path,
    raw_key: bytes,
    algo_name: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> None:
    """
    Encrypt *src_path* into *dst_path* using chunk-based AES-GCM streaming.
 
    Works for both symmetric keys (raw_key is the 32-byte key directly) and
    asymmetric keys (raw_key is the RSA private-key PEM; a fresh ephemeral
    DEK is generated and RSA-OAEP wrapped into the header).
 
    Args:
        src_path:          Plaintext source file path.
        dst_path:          Destination path for the encrypted output.
                           Must not already exist (caller enforces this).
        raw_key:           32-byte symmetric key  OR  RSA private-key PEM bytes.
        algo_name:         Algorithm name string (e.g. "AES256", "RS256").
        chunk_size:        Plaintext bytes per chunk. Default 64 KiB.
        progress_callback: Optional callable(bytes_done, total_bytes).
                           Called after each chunk is written.
 
    Raises:
        ValueError  – if src_path does not exist or dst_path already exists.
        OSError     – on any I/O failure (tmp file is cleaned up).
    """
    if not src_path.is_file():
        raise ValueError(f"Source path is not a file: {src_path}")
    if dst_path.exists():
        raise ValueError(f"Destination already exists: {dst_path}")
 
    is_asymmetric = _is_asymmetric_key(raw_key)
 
    if is_asymmetric:
        ephemeral_dek = generate_secure_bytes(32)
        wrapped_dek = _rsa_wrap_dek(raw_key, ephemeral_dek)
        enc_key = ephemeral_dek
        mac_key = ephemeral_dek[:32]
    else:
        wrapped_dek = b""
        enc_key = raw_key
        mac_key = raw_key[:32]
 
    total_bytes = src_path.stat().st_size
    chunk_count = _calculate_chunk_count(total_bytes, chunk_size)
 
    tmp_path = dst_path.with_suffix(dst_path.suffix + ".tmp")
 
    try:
        with (
            open(src_path, "rb") as src,
            open(tmp_path, "wb") as dst,
        ):
            header = _build_header(
                algo_name=algo_name,
                chunk_size=chunk_size,
                chunk_count=chunk_count,
                wrapped_dek=wrapped_dek,
                mac_key=mac_key,
            )
            dst.write(header)
 
            bytes_done = 0
            actual_count = 0
 
            for plaintext_chunk in _iter_chunks(src, chunk_size):
                ciphertext_chunk = encrypt_envelope(plaintext_chunk, enc_key)
                dst.write(_UINT32.pack(len(ciphertext_chunk)))
                dst.write(ciphertext_chunk)
 
                bytes_done += len(plaintext_chunk)
                actual_count += 1
 
                if progress_callback:
                    progress_callback(bytes_done, total_bytes)
 
            # ── validate actual chunk count matches header
            # (Only differs if file grew/shrank between stat and read — rare
            #  but handled: rewrite the header with the correct count.)
            if actual_count != chunk_count:
                dst.flush()
                _rewrite_header_chunk_count(
                    tmp_path, algo_name, chunk_size, actual_count,
                    wrapped_dek, mac_key,
                )

        tmp_path.rename(dst_path)
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        raise
 
    finally:
        if is_asymmetric:
            ephemeral_dek = b"\x00" * len(ephemeral_dek)
 
def decrypt_file_stream(
    src_path: Path,
    dst_path: Path,
    raw_key: bytes,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> str:
    """
    Decrypt an MKMS-encrypted file produced by encrypt_file_stream.
 
    Args:
        src_path:          Encrypted source file path.
        dst_path:          Destination path for plaintext output.
                           Must not already exist (caller enforces this).
        raw_key:           32-byte symmetric key  OR  RSA private-key PEM bytes.
        progress_callback: Optional callable(chunks_done, total_chunks).
 
    Returns:
        algo_name – the algorithm name string stored in the file header.
 
    Raises:
        ValueError  – on header corruption, HMAC mismatch, or bad ciphertext.
        OSError     – on any I/O failure (tmp file is cleaned up).
    """
    if not src_path.is_file():
        raise ValueError(f"Source path is not a file: {src_path}")
    if dst_path.exists():
        raise ValueError(f"Destination already exists: {dst_path}")
 
    tmp_path = dst_path.with_suffix(dst_path.suffix + ".tmp")
 
    try:
        with (
            open(src_path, "rb") as src,
            open(tmp_path, "wb") as dst,
        ):
            header_start = src.tell()
            algo_name, chunk_size, chunk_count, wrapped_dek, stored_hmac = (
                _parse_header(src)
            )
            header_end = src.tell()
 
            # Re-read the header bytes (minus the trailing 32-byte HMAC)
            # to verify integrity.
            src.seek(header_start)
            header_bytes_without_hmac = src.read(header_end - header_start - 32)
            src.seek(header_end)
 
            # Resolve the decryption key.
            is_asymmetric = bool(wrapped_dek)
            if is_asymmetric:
                dec_key = _rsa_unwrap_dek(raw_key, wrapped_dek)
                mac_key = dec_key[:32]
            else:
                dec_key = raw_key
                mac_key = raw_key[:32]
 
            # Verify HMAC.
            expected_hmac = _hmac_header(mac_key, header_bytes_without_hmac)
            if not hmac.compare_digest(stored_hmac, expected_hmac):
                raise ValueError(
                    "Header HMAC verification failed. "
                    "The file header has been tampered with or the wrong key was supplied."
                )
 
            for chunk_idx in range(chunk_count):
                len_data = src.read(4)
                if len(len_data) != 4:
                    raise ValueError(
                        f"Unexpected EOF reading chunk {chunk_idx + 1} length field."
                    )
                (ciphertext_len,) = _UINT32.unpack(len_data)
 
                ciphertext_chunk = src.read(ciphertext_len)
                if len(ciphertext_chunk) != ciphertext_len:
                    raise ValueError(
                        f"Truncated chunk {chunk_idx + 1}: "
                        f"expected {ciphertext_len} bytes, got {len(ciphertext_chunk)}."
                    )
 
                try:
                    plaintext_chunk = decrypt_envelope(ciphertext_chunk, dec_key)
                except Exception as e:
                    raise ValueError(
                        f"Authentication failure on chunk {chunk_idx + 1}: {e}"
                    ) from e
 
                dst.write(plaintext_chunk)
 
                if progress_callback:
                    progress_callback(chunk_idx + 1, chunk_count)
 
        tmp_path.rename(dst_path)
 
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        raise
 
    finally:
        if locals().get('is_asymmetric') and 'dec_key' in dir():
            try:
                dec_key = b"\x00" * len(dec_key)
            except Exception:
                pass
 
    return algo_name


# ── asymmetric DEK wrapping ──────────────────────────────────────────────────

def _is_asymmetric_key(key_bytes: bytes) -> bool:
    """Heuristic: RSA PEM keys start with '-----BEGIN'."""
    return key_bytes.lstrip()[:10] == b"-----BEGIN"
 
 
def _rsa_wrap_dek(private_pem: bytes, dek: bytes) -> bytes:
    """
    RSA-OAEP encrypt the DEK with the *public* key derived from private_pem.
    The public key is used for wrapping so any holder of the private key
    can unwrap — consistent with the rest of the codebase's hybrid model.
    """
    private_key = serialization.load_pem_private_key(private_pem, password=None)
    public_key = private_key.public_key()
 
    if not hasattr(public_key, "encrypt"):
        raise TypeError(
            "Loaded public key does not support encryption. "
            "Only RSA asymmetric keys are supported for DEK wrapping."
        )
 
    return public_key.encrypt(
        dek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
 
 
def _rsa_unwrap_dek(private_pem: bytes, wrapped_dek: bytes) -> bytes:
    """RSA-OAEP decrypt the wrapped DEK using the private key."""
    private_key = serialization.load_pem_private_key(private_pem, password=None)
 
    if not hasattr(private_key, "decrypt"):
        raise TypeError(
            "Loaded private key does not support decryption. "
            "Only RSA asymmetric keys are supported for DEK unwrapping."
        )
 
    return private_key.decrypt(
        wrapped_dek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

# ── internal utilities ───────────────────────────────────────────────────────

def _calculate_chunk_count(total_bytes: int, chunk_size: int) -> int:
    """Number of chunks needed for total_bytes with given chunk_size."""
    if total_bytes == 0:
        return 0
    return (total_bytes + chunk_size - 1) // chunk_size
 
 
def _rewrite_header_chunk_count(
    file_path: Path,
    algo_name: str,
    chunk_size: int,
    actual_count: int,
    wrapped_dek: bytes,
    mac_key: bytes,
) -> None:
    """
    Rewrite the header in-place with the corrected chunk_count.
    Called only when the file changed size between stat() and read().
    """
    corrected_header = _build_header(
        algo_name=algo_name,
        chunk_size=chunk_size,
        chunk_count=actual_count,
        wrapped_dek=wrapped_dek,
        mac_key=mac_key,
    )
 
    with open(file_path, "r+b") as f:
        f.seek(0)
        f.write(corrected_header)