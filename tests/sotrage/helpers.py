from storage.sqlite import SQLiteStorage


def insert_logical_key(
    storage: SQLiteStorage, name: str = "test-key", purpose: str = "encryption"
) -> int:
    with storage.transaction() as conn:
        conn.execute(
            "INSERT INTO logical_keys (name, purpose) VALUES (?, ?);",
            (name, purpose),
        )
        row = conn.execute(
            "SELECT _id FROM logical_keys WHERE name = ?;", (name,)
        ).fetchone()
    assert row is not None
    return row[0]


def insert_key_version(
    storage: SQLiteStorage,
    logical_key_id: int,
    kid: str,
    version: int,
    state: str = "active",
    algorithm: str = "aes-256-gcm",
    raw_material: str = "encrypted-material",
) -> None:
    with storage.transaction() as conn:
        conn.execute(
            """
            INSERT INTO key_versions
                (kid, logical_key_id, version, state, algorithm, raw_material)
            VALUES (?, ?, ?, ?, ?, ?);
            """,
            (kid, logical_key_id, version, state, algorithm, raw_material),
        )
