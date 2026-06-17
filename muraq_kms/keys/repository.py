from typing import Optional, Any
from datetime import datetime, timezone

from muraq_kms.storage.pool import StoragePool
from muraq_kms.keys.models import KeyVersionModel, KeyVersionState

class KeyRepository:
    def __init__(self, pool:StoragePool) -> None:
        self.pool = pool
    
    async def create_logical_key_async(self, name:str, purpose: str, description:Optional[str], exportable: int, 
        borrowable: int, borrow_ttl: int) -> dict[str, Any]:
        sql = """
        INSERT INTO logical_keys (name, purpose, description, exportable, borrowable, borrow_ttl_seconds, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        RETURNING _id, name, purpose, description, exportable, borrowable, borrow_ttl_seconds, created_at;
        """
        row = None
        async with self.pool.async_backend.transaction(domain='keys') as conn:
            cursor = conn.execute(sql,
            (name, purpose, description, exportable, borrowable, borrow_ttl, datetime.now(tz=timezone.utc).timestamp()))
            row = cursor.fetchone()
        
        if not row:
            raise RuntimeError(f"Failed to create key {name}.")

        return {
            "_id": row[0], "name": row[1], "purpose": row[2], "description": row[3],
            "exportable": int(row[4]), "borrowable": int(row[5]), "borrow_ttl_seconds": int(row[6])
        }

    def create_logical_key_sync(self, name:str, purpose: str, description:Optional[str], exportable: int, 
        borrowable: int, borrow_ttl: int) -> dict[str, Any]:
        sql = """
        INSERT INTO logical_keys (name, purpose, description, exportable, borrowable, borrow_ttl_seconds, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        RETURNING _id, name, purpose, description, exportable, borrowable, borrow_ttl_seconds, created_at;
        """
        row = None
        with self.pool.sync_backend.transaction(domain='keys') as conn:
            cursor = conn.execute(sql,
            (name, purpose, description, exportable, borrowable, borrow_ttl, datetime.now(tz=timezone.utc).timestamp()))
            row = cursor.fetchone()
        
        if not row:
            raise RuntimeError(f"Failed to create key {name}.")

        return {
            "_id": row[0], "name": row[1], "purpose": row[2], "description": row[3],
            "exportable": int(row[4]), "borrowable": int(row[5]), "borrow_ttl_seconds": int(row[6])
        }
    
    async def get_logical_key_by_name_async(self, name:str) -> Optional[dict[str, Any]]:
        sql = "SELECT _id, name, purpose, description, exportable, borrowable, borrow_ttl_seconds, created_at FROM logical_keys WHERE name = ?;"
        row = await self.pool.async_backend.fetchone(sql, (name,))
        if not row: return None
        return {
            "_id": row[0], "name": row[1], "purpose": row[2],
            "description": row[3], "exportable": int(row[4]), "borrowable": int(row[5]),
            "borrow_ttl_seconds": int(row[6]), "created_at": row[7]
        }
    
    def get_logical_key_by_name_sync(self, name:str) -> Optional[dict[str, Any]]:
        sql = "SELECT _id, name, purpose, description, exportable, borrowable, borrow_ttl_seconds, created_at FROM logical_keys WHERE name = ?;"
        row = self.pool.sync_backend.fetchone(sql, (name,))
        if not row: return None
        return {
            "_id": row[0], "name": row[1], "purpose": row[2],
            "description": row[3], "exportable": int(row[4]), "borrowable": int(row[5]),
            "borrow_ttl_seconds": int(row[6]), "created_at": row[7]
        }
    
    async def save_key_version_async(self, model:KeyVersionModel) -> dict[str, Any]:
        sql = """
        INSERT INTO key_versions (kid, logical_key_id, version, state, algorithm, raw_material, created_at, activated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING kid, logical_key_id, version, state, algorithm, raw_material, created_at, activated_at;
        """
        row = None
        async with self.pool.async_backend.transaction(domain='keys') as conn:
            cursor = conn.execute(
                sql, (model.kid, model.logical_key_id, 
                model.version, model.state.value, model.algorithm, 
                model.raw_material, model.created_at.timestamp(), 
                model.activated_at.timestamp() if model.activated_at else None)
            )
            row = cursor.fetchone()

        if not row:
            raise RuntimeError(f"Failed to save key version {model.kid}.")

        return {
            "kid": row[0], "logical_key_id": row[1], "version": row[2], 
            "state": row[3], "algorithm": row[4], "raw_material": row[5],
            "created_at": row[6], "activated_at": row[7]
        }
    
    def save_key_version_sync(self, model:KeyVersionModel) -> None:
        sql = """
        INSERT INTO key_versions (kid, logical_key_id, version, state, algorithm, raw_material, created_at, activated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING kid, logical_key_id, version, state, algorithm, raw_material, created_at, activated_at;
        """
        row = None
        with self.pool.sync_backend.transaction(domain='keys') as conn:
            cursor = conn.execute(
                sql, (model.kid, model.logical_key_id, 
                model.version, model.state.value, model.algorithm, 
                model.raw_material, model.created_at.timestamp(), 
                model.activated_at.timestamp() if model.activated_at else None)
            )
            row = cursor.fetchone()

        if not row:
            raise RuntimeError(f"Failed to save key version {model.kid}.")

        return {
            "kid": row[0], "logical_key_id": row[1], "version": row[2], 
            "state": row[3], "algorithm": row[4], "raw_material": row[5],
            "created_at": row[6], "activated_at": row[7]
        }

    async def get_key_version_by_kid_async(self, kid: int) -> Optional[dict[str, Any]]:
        sql = "SELECT kid, logical_key_id, version, state, algorithm, raw_material, created_at FROM key_versions WHERE kid = ?;"
        row = await self.pool.async_backend.fetchone(sql, (kid,))
        if not row: return None
        return {
            "kid": row[0], "logical_key_id": row[1], "version": row[2], 
            "state": row[3], "algorithm": row[4], "raw_material": row[5],
            "created_at": row[6]
        }
    
    def get_key_version_by_kid_sync(self, kid: int) -> Optional[dict[str, Any]]:
        sql = "SELECT kid, logical_key_id, version, state, algorithm, raw_material, created_at FROM key_versions WHERE kid = ?;"
        row = self.pool.sync_backend.fetchone(sql, (kid,))
        if not row: return None
        return {
            "kid": row[0], "logical_key_id": row[1], "version": row[2], 
            "state": row[3], "algorithm": row[4], "raw_material": row[5],
            "created_at": row[6]
        }
    
    async def get_key_version_async(self, lk_id: int) -> Optional[dict[str, Any]]:
        sql = "SELECT kid, logical_key_id, version, state, algorithm, raw_material, created_at FROM key_versions WHERE logical_key_id = ?;"
        row = await self.pool.async_backend.fetchone(sql, (lk_id,))
        if not row: return None
        return {
            "kid": row[0], "logical_key_id": row[1], "version": row[2], 
            "state": row[3], "algorithm": row[4], "raw_material": row[5],
            "created_at": row[6]
        }
    
    def get_key_version_sync(self, lk_id: int) -> Optional[dict[str, Any]]:
        sql = "SELECT kid, logical_key_id, version, state, algorithm, raw_material, created_at FROM key_versions WHERE logical_key_id = ?;"
        row = self.pool.sync_backend.fetchone(sql, (lk_id,))
        if not row: return None
        return {
            "kid": row[0], "logical_key_id": row[1], "version": row[2], 
            "state": row[3], "algorithm": row[4], "raw_material": row[5],
            "created_at": row[6]
        }
    
    async def get_active_version_for_logical_key_async(self, logical_key_id: int) -> Optional[dict[str, Any]]:
        sql = "SELECT kid, logical_key_id, version, state, algorithm, raw_material FROM key_versions WHERE logical_key_id = ? AND state = 'active' LIMIT 1;"
        row = await self.pool.async_backend.fetchone(sql, (logical_key_id,))
        if not row: return None
        return {
            "kid": row[0], "logical_key_id": row[1], "version": row[2], 
            "state": row[3], "algorithm": row[4], "raw_material": row[5]
        }
    
    def get_active_version_for_logical_key_sync(self, logical_key_id: int) -> Optional[dict[str, Any]]:
        sql = "SELECT kid, logical_key_id, version, state, algorithm, raw_material FROM key_versions WHERE logical_key_id = ? AND state = 'active' LIMIT 1;"
        row = self.pool.sync_backend.fetchone(sql, (logical_key_id,))
        if not row: return None
        return {
            "kid": row[0], "logical_key_id": row[1], "version": row[2], 
            "state": row[3], "algorithm": row[4], "raw_material": row[5]
        }

    async def update_key_state_async(self, kid: str, next_state: KeyVersionState, timestamp_field: Optional[str] = None) -> None:
        if timestamp_field:
            sql = f"UPDATE key_versions SET state = ?, {timestamp_field} = ? WHERE kid = ?;"
            await self.pool.async_backend.execute(sql, (next_state.value, datetime.now(tz=timezone.utc).timestamp(), kid))
        else:
            sql = "UPDATE key_versions SET state = ? WHERE kid = ?;"
            await self.pool.async_backend.execute(sql, (next_state.value, kid))
    
    def update_key_state_sync(self, kid: str, next_state: KeyVersionState, timestamp_field: Optional[str] = None) -> None:
        if timestamp_field:
            sql = f"UPDATE key_versions SET state = ?, {timestamp_field} = ? WHERE kid = ?;"
            self.pool.sync_backend.execute(sql, (next_state.value, datetime.now(tz=timezone.utc).timestamp(), kid))
        else:
            sql = "UPDATE key_versions SET state = ? WHERE kid = ?;"
            self.pool.sync_backend.execute(sql, (next_state.value, kid))
    
    async def add_dependency_async(self, ciphertext_id: str, ref_kid: str, status: str) -> None:
        sql = "INSERT INTO key_dependencies (ciphertext_id, ref_kid, status, registered_at) VALUES (?, ?, ?, ?);"
        await self.pool.async_backend.execute(sql, (ciphertext_id, ref_kid, status, datetime.now(tz=timezone.utc).timestamp()))
    
    def add_dependency_sync(self, ciphertext_id: str, ref_kid: str, status: str) -> None:
        sql = "INSERT INTO key_dependencies (ciphertext_id, ref_kid, status, registered_at) VALUES (?, ?, ?, ?);"
        self.pool.sync_backend.execute(sql, (ciphertext_id, ref_kid, status, datetime.now(tz=timezone.utc).timestamp()))

    async def get_dependency_count_async(self, kid: str) -> int:
        sql = "SELECT COUNT(*) FROM key_dependencies WHERE ref_kid = ? AND status IN ('coupled', 'migrating');"
        row = await self.pool.async_backend.fetchone(sql, (kid,))
        return row[0] if row else 0
    
    def get_dependency_count_sync(self, kid: str) -> int:
        sql = "SELECT COUNT(*) FROM key_dependencies WHERE ref_kid = ? AND status IN ('coupled', 'migrating');"
        row = self.pool.sync_backend.fetchone(sql, (kid,))
        return row[0] if row else 0

    async def update_dependency_status_async(self, ciphertext_id: str, status: str) -> None:
        sql = "UPDATE key_dependencies SET status = ? WHERE ciphertext_id = ?;"
        await self.pool.async_backend.execute(sql, (status, ciphertext_id))
    
    def update_dependency_status_sync(self, ciphertext_id: str, status: str) -> None:
        sql = "UPDATE key_dependencies SET status = ? WHERE ciphertext_id = ?;"
        self.pool.sync_backend.execute(sql, (status, ciphertext_id))