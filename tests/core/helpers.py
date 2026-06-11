import sqlite3
from pathlib import Path

def create_corrupt_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"INVALID_JUNK_DATA_NOT_SQLITE_OR_JSON_PADDING")

def create_valid_sqlite(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY);")