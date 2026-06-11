import hmac
import hashlib
import json
from typing import Dict, Any

def calculate_manifest_signature(manifest:Dict[str, Any], integrity_key:bytes) -> bytes:
    serialized_manifest = json.dumps(manifest, sort_keys=True, separators=(',', ':'))
    manifest_bytes = serialized_manifest.encode("utf-8")

    return hmac.new(integrity_key, manifest_bytes, hashlib.sha256).digest()

def verify_manifest_signature(manifest_data:Dict[str, Any], signature:bytes, integrity_key:bytes) -> bool:
    expected = calculate_manifest_signature(manifest_data, integrity_key)
    return hmac.compare_digest(expected, signature)