"""
muraq_kms/cli/services/crypto_service.py
 
CLI service handlers for encrypt / decrypt commands.
 
Routing logic:
  -m (inline message)  →  spec.encrypt_hook / spec.decrypt_hook
                          fully in-memory, output as base64 or hex string
  -f (file path)       →  spec.stream_encrypt_hook / spec.stream_decrypt_hook
                          chunk-streamed, constant memory, raw binary output
"""
from __future__ import annotations

from argparse import Namespace
from pathlib import Path

from base64 import b64encode, b64decode

from muraq_kms.cli.ui.ui import UI
from muraq_kms.cli.ui.widgets import ProgressIndicator, Frame

from muraq_kms.crypto.primitives import decrypt_envelope

from muraq_kms.crypto.registry import MuraqKMSAlgorithms, AlgorithmSpec

from muraq_kms.keys.manager import KeyManager


# ── shared helpers ────────────────────────────────────────────────────────────

def _resolve_key_material(
    key_manager: KeyManager,
    rmk: bytes,
    key_name: str,
) -> tuple[bytes, str] | tuple[None, None]:
    """
    Look up the active key version by name, unwrap the raw material.
 
    Returns (raw_key_bytes, algo_name) or (None, None) on any failure.
    """
    kv = key_manager.get_key_version_sync(key_name)
    if not kv:
        print(
            f"{UI.STATUS.FAIL} Key Reference Error: "
            f"No active cryptographic key found named '{key_name}'."
        )
        return None, None
    
    lk = key_manager.get_logical_key_sync(logical_key_id=kv.logical_key_id)
    if not lk:
        print(f"{UI.STATUS.FAIL} Key Reference Error: No active cryptographic key variant found named '{key_name}'.")
        return None, None
    
    can_encrypt:bool = lk['purpose'] == "encryption"

    if not can_encrypt:
        print(f"{UI.STATUS.FAIL} Key Reference Error: Key '{key_name}' can not perform 'encryption'.")
        return None, None
 
    try:
        raw_key = decrypt_envelope(bytes.fromhex(kv.raw_material), rmk)
    except Exception as e:
        print(
            f"{UI.STATUS.FAIL} Key Unwrap Failure: "
            f"Could not decrypt key material — {e}"
        )
        return None, None
 
    return raw_key, kv.algorithm

# ── encryption ────────────────────────────────────────────────────────────────

def handle_encryption(key_manager:KeyManager, rmk:bytes, args:Namespace):
    """
    Dispatch point for the `encrypt` CLI command.
 
    -m / --message  → in-memory encrypt_hook, print base64 or hex to stdout
                       (or write to -o file if specified)
    -f / --file     → streaming stream_encrypt_hook, always writes to disk
    """
    raw_key, algo_name = _resolve_key_material(key_manager, rmk, args.key)
    if raw_key is None:
        return

    try:
        spec = MuraqKMSAlgorithms.get_spec(algo_name)
    except ValueError as e:
        print(f"{UI.STATUS.FAIL} Algorithm Registry Error: {e}")
        return
    
    is_file = bool(args.file)

    if is_file:
        _encrypt_file(spec, raw_key, algo_name, args)
    else:
        _encrypt_message(spec, raw_key, args)

def _encrypt_message(spec:AlgorithmSpec, raw_key: bytes, args: Namespace) -> None:
    """In-memory path: -m / --message"""
    msg_bytes = args.message.encode("utf-8")
    out_format = args.format or "base64"
 
    print(f"{UI.STATUS.INFO} Encrypting message with [{spec.name}]...")
 
    try:
        ciphertext = spec.encrypt_hook(msg_bytes, raw_key)
    except Exception as e:
        print(f"{UI.STATUS.FAIL} Cryptographic Engine Failure: {e}")
        return
 
    # if out_format == "base64":
    #     encoded = b64encode(ciphertext).decode("utf-8")
    # elif out_format == "hex":
    #     encoded = ciphertext.hex()
    # else:
    #     print(
    #         f"{UI.STATUS.FAIL} Presentation Error: Raw binary cannot be written to "
    #         "stdout. Use '--format base64', '--format hex', or specify '-o <path>'."
    #     )
    #     return
 
    if args.output:
        output_path = Path(args.output)
        if output_path.is_dir():
            output_path = output_path / "encrypted_output.enc"
 
        if output_path.exists():
            print(
                f"{UI.STATUS.FAIL} Write Protection: "
                f"'{output_path}' already exists. Operation aborted."
            )
            return
 
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            if out_format == "base64":
                encoded = b64encode(ciphertext).decode("utf-8")
                output_path.write_text(encoded, encoding='utf-8')
            elif out_format == "hex":
                encoded = ciphertext.hex()
                output_path.write_text(encoded, encoding="utf-8")
            elif out_format == "raw":
                output_path.write_bytes(ciphertext)
            else:
                print(
                    f"{UI.STATUS.FAIL} Encoding Error: '{out_format}' is not defined"
                    "Use '--format base64', '--format hex', or '--format raw'."
                )
                return
            print(
                f"{UI.STATUS.SUCCESS} Ciphertext [{spec.name}] written to: {output_path}"
            )
        except OSError as e:
            print(f"{UI.STATUS.FAIL} Write Failure: {e}")
        return
    
    if out_format == "base64":
        encoded = b64encode(ciphertext).decode("utf-8")
    elif out_format == "hex":
        encoded = ciphertext.hex()
    else:
        print(
            f"{UI.STATUS.FAIL} Presentation Error: Raw binary cannot be written to "
            "stdout. Use '--format base64', '--format hex', or specify '-o <path>'."
        )
        return
 
    print(f"\n{UI.STATUS.SUCCESS} Encryption complete [{spec.name}]:")
    with Frame("CIPHERTEXT OUTPUT", color=UI.COLORS.CYAN) as frame:
        for i in range(0, len(encoded), 80):
            frame.line(encoded[i : i + 80])
    print()

def _encrypt_file(spec:AlgorithmSpec, raw_key: bytes, algo_name: str, args: Namespace) -> None:
    """Streaming path: -f / --file"""
    src_path = Path(args.file)
 
    if not src_path.is_file():
        print(
            f"{UI.STATUS.FAIL} Filesystem Error: "
            f"'{args.file}' is not a valid file."
        )
        return
 
    if args.output:
        target = Path(args.output)
        if target.is_dir():
            dst_path = target / f"{src_path.stem}_enc{src_path.suffix}"
        else:
            dst_path = target
    else:
        dst_path = src_path.with_name(f"{src_path.stem}_enc{src_path.suffix}")
 
    if dst_path.exists():
        print(
            f"{UI.STATUS.FAIL} Write Protection: "
            f"'{dst_path}' already exists. Operation aborted."
        )
        return
 
    file_size_mb = src_path.stat().st_size / (1024 * 1024)
    print(
        f"{UI.STATUS.INFO} Streaming encryption [{spec.name}] — "
        f"{file_size_mb:.1f} MiB  →  {dst_path.name}"
    )
 
    try:
        spec.stream_encrypt_hook(
            src_path,
            dst_path,
            raw_key,
            algo_name,
            progress_callback=ProgressIndicator.build(),
        )
    except Exception as e:
        print(f"\n{UI.STATUS.FAIL} Streaming Encryption Failure: {e}")
        return
 
    enc_size_mb = dst_path.stat().st_size / (1024 * 1024)
    print(
        f"{UI.STATUS.SUCCESS} File encrypted [{spec.name}]: "
        f"{file_size_mb:.1f} MiB → {enc_size_mb:.1f} MiB"
    )
    print(f"   {UI.ANSIESCAPE.DIM}└─ Output: {dst_path}{UI.ANSIESCAPE.RESET}\n")

# ── decryption ────────────────────────────────────────────────────────────────

def handle_decryption(key_manager:KeyManager, rmk:bytes, args:Namespace):
    """
    Dispatch point for the `decrypt` CLI command.
 
    -m / --message  → in-memory decrypt_hook, print plaintext to stdout
                       (or write to -o file if specified)
    -f / --file     → streaming stream_decrypt_hook, always writes to disk
    """
    raw_key, algo_name = _resolve_key_material(key_manager, rmk, args.key)
    if raw_key is None:
        return
    
    try:
        spec = MuraqKMSAlgorithms.get_spec(algo_name)
    except ValueError as e:
        print(f"{UI.STATUS.FAIL} Algorithm Registry Error: {e}")
        return
    
    is_file = bool(args.file)

    if is_file:
        _decrypt_file(spec, raw_key, args)
    else:
        _decrypt_message(spec, raw_key, args)

def _decrypt_message(spec:AlgorithmSpec, raw_key: bytes, args: Namespace) -> None:
    """In-memory path: -m / --message"""
    in_format = args.format or "base64"
 
    try:
        if in_format == "base64":
            ciphertext = b64decode(args.message)
        elif in_format == "hex":
            ciphertext = bytes.fromhex(args.message)
        else:
            ciphertext = args.message.encode("latin-1")
    except Exception as e:
        print(
            f"{UI.STATUS.FAIL} Deserialisation Error: "
            f"Could not decode '{in_format}' payload — {e}"
        )
        return
 
    print(f"{UI.STATUS.INFO} Decrypting message with [{spec.name}]...")
 
    try:
        plaintext = spec.decrypt_hook(ciphertext, raw_key)
    except Exception as e:
        print(
            f"{UI.STATUS.FAIL} Decryption Failure: "
            f"Authentication or key mismatch — {e}"
        )
        return
 
    try:
        plaintext_str = plaintext.decode("utf-8")
        is_text = True
    except UnicodeDecodeError:
        plaintext_str = plaintext.hex()
        is_text = False
 
    if args.output:
        output_path = Path(args.output)
        if output_path.is_dir():
            output_path = output_path / "decrypted_output.txt"
 
        if output_path.exists():
            print(
                f"{UI.STATUS.FAIL} Write Protection: "
                f"'{output_path}' already exists. Operation aborted."
            )
            return
 
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            if is_text:
                output_path.write_text(plaintext_str, encoding="utf-8")
            else:
                output_path.write_bytes(plaintext)
            print(
                f"{UI.STATUS.SUCCESS} Plaintext [{spec.name}] written to: {output_path}"
            )
        except OSError as e:
            print(f"{UI.STATUS.FAIL} Write Failure: {e}")
        return
 
    label = "PLAINTEXT OUTPUT" if is_text else "PLAINTEXT OUTPUT (hex — non-UTF-8 bytes)"
    print(f"\n{UI.STATUS.SUCCESS} Decryption complete [{spec.name}]:")
    with Frame(label, color=UI.COLORS.GREEN) as frame:
        for i in range(0, len(plaintext_str), 80):
            frame.line(plaintext_str[i : i + 80])
    print()

def _decrypt_file(spec:AlgorithmSpec, raw_key: bytes, args: Namespace) -> None:
    """Streaming path: -f / --file"""
    src_path = Path(args.file)
 
    if not src_path.is_file():
        print(
            f"{UI.STATUS.FAIL} Filesystem Error: "
            f"'{args.file}' is not a valid file."
        )
        return
 
    if args.output:
        target = Path(args.output)
        if target.is_dir():
            stem = src_path.stem
            if stem.endswith("_enc"):
                stem = stem[:-4]
            dst_path = target / f"{stem}_dec{src_path.suffix}"
        else:
            dst_path = target
    else:
        stem = src_path.stem
        if stem.endswith("_enc"):
            stem = stem[:-4]
        dst_path = src_path.with_name(f"{stem}_dec{src_path.suffix}")
 
    if dst_path.exists():
        print(
            f"{UI.STATUS.FAIL} Write Protection: "
            f"'{dst_path}' already exists. Operation aborted."
        )
        return
 
    file_size_mb = src_path.stat().st_size / (1024 * 1024)
    print(
        f"{UI.STATUS.INFO} Streaming decryption [{spec.name}] — "
        f"{file_size_mb:.1f} MiB  →  {dst_path.name}"
    )
 
    try:
        detected_algo = spec.stream_decrypt_hook(
            src_path,
            dst_path,
            raw_key,
            progress_callback=ProgressIndicator.build(mode="chunk"),
        )
    except ValueError as e:
        print(f"\n{UI.STATUS.FAIL} Integrity / Decryption Error: {e}")
        return
    except Exception as e:
        print(f"\n{UI.STATUS.FAIL} Streaming Decryption Failure: {e}")
        return
 
    dec_size_mb = dst_path.stat().st_size / (1024 * 1024)
    print(
        f"{UI.STATUS.SUCCESS} File decrypted [{detected_algo}]: "
        f"{file_size_mb:.1f} MiB → {dec_size_mb:.1f} MiB"
    )
    print(f"   {UI.ANSIESCAPE.DIM}└─ Output: {dst_path}{UI.ANSIESCAPE.RESET}\n")