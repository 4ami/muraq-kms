import pytest
import io
import struct
from pathlib import Path
from unittest.mock import patch, MagicMock

from muraq_kms.crypto.streaming import (
    _calculate_chunk_count,
    _hmac_header,
    _iter_chunks,
    _build_header,
    _parse_header,
    _is_asymmetric_key,
    encrypt_file_stream,
    decrypt_file_stream,
    MAGIC,
    VERSION
)

# ── helper calculation unit tests ───────────────────────────────────────────

@pytest.mark.parametrize("total_bytes, chunk_size, expected_chunks", [
    (0, 4096, 0),
    (1, 4096, 1),
    (4096, 4096, 1),
    (4097, 4096, 2),
    (10000, 2000, 5),
])
def test_calculate_chunk_count_invariants(total_bytes, chunk_size, expected_chunks):
    """Verify standard math boundaries for multi-block chunk ceiling division computations."""
    assert _calculate_chunk_count(total_bytes, chunk_size) == expected_chunks

def test_iter_chunks_reads_exact_bounds():
    """Verify chunking generator splits arbitrary streams into uniform buffer segments."""
    raw_data = b"AAAABBBBCCCCD"
    stream = io.BytesIO(raw_data)
    
    chunks = list(_iter_chunks(stream, chunk_size=4))
    
    assert chunks == [b"AAAA", b"BBBB", b"CCCC", b"D"]

def test_is_asymmetric_key_heuristics():
    """Verify that key layout heuristics differentiate symmetric keys from PEM headers."""
    assert _is_asymmetric_key(b"-----BEGIN PRIVATE KEY-----") is True
    assert _is_asymmetric_key(b"   -----BEGIN PRIVATE KEY-----") is True
    assert _is_asymmetric_key(b"\x00" * 32) is False

# ── header framing unit tests ────────────────────────────────────────────────

def test_build_header_serialization_layout():
    """Ensure header structure bytes line up cleanly with the target layout format specs."""
    algo_name = "AES256"
    chunk_size = 65536
    chunk_count = 12
    wrapped_dek = b""
    mac_key = b"\x01" * 32
    
    header = _build_header(algo_name, chunk_size, chunk_count, wrapped_dek, mac_key)
    
    assert header[0:4] == MAGIC
    assert header[4:5] == b"\x01"
    
    algo_len = struct.unpack(">H", header[5:7])[0]
    assert algo_len == len(algo_name)
    assert header[7 : 7 + algo_len] == algo_name.encode("utf-8")


def test_parse_header_recovers_exact_values():
    """Verify that header serialization properties remain completely invertible."""
    algo_name = "XCHACHA20"
    chunk_size = 1024
    chunk_count = 42
    wrapped_dek = b"fake-rsa-wrapped-dek-material"
    mac_key = b"\x02" * 32
    
    serialized = _build_header(algo_name, chunk_size, chunk_count, wrapped_dek, mac_key)
    stream = io.BytesIO(serialized)
    
    p_algo, p_size, p_count, p_dek, p_hmac = _parse_header(stream)
    
    assert p_algo == algo_name
    assert p_size == chunk_size
    assert p_count == chunk_count
    assert p_dek == wrapped_dek
    
    expected_hmac = _hmac_header(mac_key, serialized[:-32])
    assert p_hmac == expected_hmac

# ── header validation & corruption unit tests ────────────────────────────────

def test_parse_header_raises_on_truncated_buffers():
    """Ensure trying to parse missing header segments raises a clear layout validation error."""
    truncated_stream = io.BytesIO(b"MKMS\x01")
    
    with pytest.raises(ValueError, match="Truncated header"):
        _parse_header(truncated_stream)


def test_parse_header_detects_corrupted_magic_bytes():
    """Ensure files missing the signature identifier reject execution during serialization passes."""
    bad_stream = io.BytesIO(b"GZIP\x01\x00\x06AES256")
    
    with pytest.raises(ValueError, match="Invalid file magic"):
        _parse_header(bad_stream)


def test_parse_header_rejects_unsupported_versions():
    """Verify that file versions greater than 0x01 trigger a version mismatch error."""
    bad_version_header = MAGIC + b"\x02" + struct.pack(">H", 6) + b"AES256"
    bad_stream = io.BytesIO(bad_version_header)
    
    with pytest.raises(ValueError, match="Unsupported format version"):
        _parse_header(bad_stream)

# ── operational stream orchestration unit tests ──────────────────────────────

def test_encrypt_file_stream_writes_valid_binary_layout(tmp_path):
    """Verify that encrypt_file_stream handles standard symmetric file encryption flows."""
    src_file = tmp_path / "plain.txt"
    dst_file = tmp_path / "cipher.enc"
    
    raw_payload = b"muraq_kms_stream_unit_payload_chunk"
    src_file.write_bytes(raw_payload)
    
    raw_key = b"\x07" * 32
    progress_calls = []
    
    def mock_cb(bytes_done, total_bytes):
        progress_calls.append((bytes_done, total_bytes))

    encrypt_file_stream(
        src_path=src_file,
        dst_path=dst_file,
        raw_key=raw_key,
        algo_name="AES256",
        chunk_size=1024,
        progress_callback=mock_cb
    )

    assert dst_file.exists()
    assert len(progress_calls) == 1
    assert progress_calls[0] == (len(raw_payload), len(raw_payload))

    with open(dst_file, "rb") as f:
        file_magic = f.read(4)
        assert file_magic == MAGIC

def test_decrypt_file_stream_recovers_original_bytes(tmp_path):
    """Verify the symmetry of the file encryption and decryption orchestration routines."""
    src_file = tmp_path / "source.txt"
    enc_file = tmp_path / "encrypted.dat"
    dec_file = tmp_path / "recovered.txt"
    
    original_bytes = b"structural_payload_data_stream"
    src_file.write_bytes(original_bytes)
    raw_key = b"\x09" * 32
    
    encrypt_file_stream(src_file, enc_file, raw_key, "AES256", chunk_size=16)
    
    progress_calls = []
    def mock_decrypt_cb(chunks_done, total_chunks):
        progress_calls.append((chunks_done, total_chunks))

    recovered_algo = decrypt_file_stream(
        src_path=enc_file,
        dst_path=dec_file,
        raw_key=raw_key,
        progress_callback=mock_decrypt_cb
    )

    assert recovered_algo == "AES256"
    assert dec_file.read_bytes() == original_bytes
    assert len(progress_calls) > 0

# ── edge cases, validations & exception constraints ───────────────────────────

def test_streaming_raises_on_preexisting_destination(tmp_path):
    """Ensure that stream encryption aborts immediately if a destination file exists."""
    src_file = tmp_path / "src.txt"
    dst_file = tmp_path / "dst.txt"
    
    src_file.write_bytes(b"data")
    dst_file.write_bytes(b"blocks")
    
    with pytest.raises(ValueError, match="Destination already exists"):
        encrypt_file_stream(src_file, dst_file, b"\x00" * 32, "AES256")


def test_decrypt_stream_raises_on_tampered_header_hmac(tmp_path):
    """Ensure that modifying header fields throws an HMAC verification error during decryption."""
    src_file = tmp_path / "clean.txt"
    enc_file = tmp_path / "tampered.dat"
    dec_file = tmp_path / "failed.txt"
    
    src_file.write_bytes(b"secure-data-block")
    raw_key = b"\x05" * 32
    
    encrypt_file_stream(src_file, enc_file, raw_key, "AES256", chunk_size=1024)
    
    raw_contents = bytearray(enc_file.read_bytes())
    raw_contents[25] ^= 0x01
    enc_file.write_bytes(bytes(raw_contents))
    
    with pytest.raises(ValueError, match="Header HMAC verification failed"):
        decrypt_file_stream(enc_file, dec_file, raw_key)

@patch("muraq_kms.crypto.streaming._iter_chunks")
def test_encrypt_stream_handles_runtime_size_drift(mock_iter, tmp_path):
    """
    Verify that if the file dynamically grows or shrinks during execution, 
    _rewrite_header_chunk_count is called to fix the file header block in-place.
    """
    src_file = tmp_path / "drift.txt"
    dst_file = tmp_path / "drift_out.enc"
    
    src_file.write_bytes(b"initial-payload-size")
    
    mock_iter.return_value = [b"chunk-data-1", b"chunk-data-2"]
    
    with patch("muraq_kms.crypto.streaming._rewrite_header_chunk_count") as mock_rewrite:
        encrypt_file_stream(src_file, dst_file, b"\x01" * 32, "AES256", chunk_size=1024)
        mock_rewrite.assert_called_once()