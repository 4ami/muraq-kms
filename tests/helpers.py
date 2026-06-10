import json
from pathlib import Path

def read_manifest(base_dir: Path) -> dict:
    manifest_path = base_dir / "manifest.json"
    with open(manifest_path, "r", encoding="utf-8") as f:
        return json.load(f)

def corrupt_file_bytes(file_path: Path) -> None:
    if file_path.exists():
        with open(file_path, "r+b") as f:
            f.write(b"\xff\xff\xff\xff")