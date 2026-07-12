from datetime import datetime, timezone
from typing import Any, List, Optional, Generator, AsyncGenerator
from contextlib import contextmanager, asynccontextmanager

from muraq_kms.storage.pool import StoragePool

from muraq_kms.crypto.primitives import encrypt_envelope, decrypt_envelope
from muraq_kms.crypto.registry import MuraqKMSAlgorithms

from muraq_kms.keys.key_errors import KeyLifecycleError
from muraq_kms.keys.repository import KeyRepository
from muraq_kms.keys.models import KeyVersionModel, KeyVersionState

from muraq_kms.audit.manager import AuditManager

from muraq_kms.policies.models import KeyAccessPolicy
from muraq_kms.policies.evaluator import PolicyEvaluator
from muraq_kms.policies.lease import borrow_key_context, EphemeralKeyLease
from muraq_kms.policies.policy_errors import PolicyDenialError

class KeyManager:
    def __init__(self, pool:StoragePool, audit_manager:AuditManager, ask:bytes, rmk:bytes, evaluator:Optional[PolicyEvaluator] = None) -> None:
        self.repo = KeyRepository(pool=pool)
        self.audit = audit_manager
        self.ask = ask
        self.rmk = rmk
        self.evaluator = evaluator or PolicyEvaluator()
    
    async def create_key_async(self, actor:str, name: str, purpose:str, algorithm: str = "XChaCha20", description: Optional[str] = None, policy: Optional[KeyAccessPolicy] = None) -> KeyVersionModel:
        """
        Creates a new logical container if missing and maps its initial v1 active key material.
        All configurations flow into your strict PolicyManifest engine.
        """
        p = policy or KeyAccessPolicy()
        spec = MuraqKMSAlgorithms.get_spec(algorithm)
        
        try:
            logical_key = await self.repo.get_logical_key_by_name_async(name)
            
            if logical_key:
                raise KeyLifecycleError(f"Key Identity Conflict: Logical key '{name}' already exists.")
            
            logical_key = await self.repo.create_logical_key_async(
                name=name, 
                purpose=purpose,
                description=description,
                exportable=1 if p.export else 0,
                borrowable=1 if p.borrow else 0,
                borrow_ttl=p.borrow_ttl_seconds if p.borrow else 0
            )
            
            v_num = 1
            kid = f"{name}:v{v_num}"
            
            raw_material = spec.generator_func()
            
            model = KeyVersionModel(
                kid=kid,
                logical_key_id=logical_key["_id"],
                version=v_num,
                state=KeyVersionState.ACTIVE,
                algorithm=algorithm,
                raw_material=encrypt_envelope(raw_material, self.rmk).hex(),
                created_at=datetime.now(timezone.utc)
            )
            model.activated_at = model.created_at
            
            await self.repo.save_key_version_async(model)
            
            await self.audit.log_event_async(
                action="kms:key_create", 
                actor=actor,
                details={"logical_key": name, "kid": kid, "algorithm": algorithm},
                status="SUCCESS", 
                ask=self.ask
            )
            return model

        except Exception as e:
            await self.audit.log_event_async(
                action="kms:key_create", 
                actor=actor,
                details={"logical_key": name, "error": str(e)},
                status="FAILED", 
                ask=self.ask
            )
            if isinstance(e, KeyLifecycleError):
                raise
            raise KeyLifecycleError(f"Failed to create key '{name}': {str(e)}")

    def create_key_sync(self, actor:str, name: str, purpose:str, algorithm: str = "XChaCha20", description: Optional[str] = None, policy: Optional[KeyAccessPolicy] = None) -> KeyVersionModel:
        """
        Creates a new logical container if missing and maps its initial v1 active key material.
        All configurations flow into your strict PolicyManifest engine.
        """
        p = policy or KeyAccessPolicy()
        spec = MuraqKMSAlgorithms.get_spec(algorithm)
        
        try:
            logical_key = self.repo.get_logical_key_by_name_sync(name)
            
            if logical_key:
                raise KeyLifecycleError(f"Key Identity Conflict: Logical key '{name}' already exists.")
            
            logical_key = self.repo.create_logical_key_sync(
                name=name,
                purpose=purpose,
                description=description,
                exportable=1 if p.export else 0,
                borrowable=1 if p.borrow else 0,
                borrow_ttl=p.borrow_ttl_seconds if p.borrow else 0
            )
            
            v_num = 1
            kid = f"{name}:v{v_num}"
            
            raw_material = spec.generator_func()
            
            model = KeyVersionModel(
                kid=kid,
                logical_key_id=logical_key["_id"],
                version=v_num,
                state=KeyVersionState.ACTIVE,
                algorithm=algorithm,
                raw_material=encrypt_envelope(raw_material, self.rmk).hex(),
                created_at=datetime.now(timezone.utc)
            )
            model.activated_at = model.created_at
            
            self.repo.save_key_version_sync(model)
            
            self.audit.log_event_sync(
                action="kms:key_create", 
                actor=actor,
                details={"logical_key": name, "kid": kid, "algorithm": algorithm},
                status="SUCCESS", 
                ask=self.ask
            )
            return model

        except Exception as e:
            self.audit.log_event_sync(
                action="kms:key_create", 
                actor=actor,
                details={"logical_key": name, "error": str(e)},
                status="FAILED", 
                ask=self.ask
            )
            if isinstance(e, KeyLifecycleError):
                raise
            raise KeyLifecycleError(f"Failed to create key '{name}': {str(e)}")
    
    @asynccontextmanager
    async def borrow_key_async(self, actor:str, name:str, version:Optional[int] = None) -> AsyncGenerator[EphemeralKeyLease, None]:
        """
        FR-14 & FR-21 Controlled Ephemeral Borrow access pattern. 
        Enforces runtime-scoped contexts, zeroization window assertions, and audit logging.
        """

        lk = await self.repo.get_logical_key_by_name_async(name=name)

        if not lk or lk['borrowable'] != 1:
            await self.audit.log_event_async(
                actor=actor,
                action="kms:borrow",
                status="DENIED",
                details={"logical_key": name},
                ask=self.ask
            )
            raise PolicyDenialError(f"Key reference '{name}' is not flagged as borrowable.")
        
        kv = None
        if version:
            kv = await self.repo.get_key_version_by_kid_async(kid=f"{name}:v{version}")
        else:
            kv = await self.repo.get_active_version_for_logical_key_async(logical_key_id=lk['_id'])
        if not kv:
            raise KeyLifecycleError("Requested target physical key layer variant is unreachable.")
        
        wrapped_key:bytes = bytes.fromhex(kv['raw_material'])
        raw_material:bytes = decrypt_envelope(wrapped_key, self.rmk)

        with borrow_key_context(key_id=kv['kid'], raw_bytes=raw_material, ttl_seconds=lk['borrow_ttl_seconds']) as lease:
            await self.audit.log_event_async(
                action="kms:borrow", actor=actor, status="SUCCESS",
                details={"kid": kv['kid'], "ttl_seconds": lk['borrow_ttl_seconds']},
                ask=self.ask
            )
            yield lease
   
    @contextmanager
    def borrow_key_sync(self, actor:str, name:str, version:Optional[int] = None) -> Generator[EphemeralKeyLease, None, None]:
        """
        FR-14 & FR-21 Controlled Ephemeral Borrow access pattern. 
        Enforces runtime-scoped contexts, zeroization window assertions, and audit logging.
        """

        lk = self.repo.get_logical_key_by_name_sync(name=name)
        if not lk or lk['borrowable'] != 1:
            self.audit.log_event_sync(
                actor=actor,
                action="kms:borrow",
                status="DENIED",
                details={"logical_key": name},
                ask=self.ask
            )
            raise PolicyDenialError(f"Key reference '{name}' is not flagged as borrowable.")
        
        kv = None
        if version:
            kv = self.repo.get_key_version_by_kid_sync(kid=f"{name}:v{version}")
        else:
            kv = self.repo.get_active_version_for_logical_key_sync(logical_key_id=lk['_id'])
        if not kv:
            raise KeyLifecycleError("Requested target physical key layer variant is unreachable.")
        
        wrapped_key:bytes = bytes.fromhex(kv['raw_material'])
        raw_material:bytes = decrypt_envelope(wrapped_key, self.rmk)

        with borrow_key_context(key_id=kv['kid'], raw_bytes=raw_material, ttl_seconds=lk['borrow_ttl_seconds']) as lease:
            self.audit.log_event_sync(
                action="kms:borrow", actor=actor, status="SUCCESS",
                details={"kid": kv['kid'], "ttl_seconds": lk['borrow_ttl_seconds']},
                ask=self.ask
            )
            yield lease
    
    async def get_key_version_async(self, name:str) -> Optional[KeyVersionModel]:
        lk = await self.repo.get_logical_key_by_name_async(name=name)
        
        if not lk:
            return None
        
        kv = await self.repo.get_active_version_for_logical_key_async(logical_key_id=lk['_id'])

        if not kv:
            return None
        
        return KeyVersionModel(**kv)
    
    def get_key_version_sync(self, name:str) -> Optional[KeyVersionModel]:
        lk = self.repo.get_logical_key_by_name_sync(name=name)
        
        if not lk:
            return None
        
        kv = self.repo.get_active_version_for_logical_key_sync(logical_key_id=lk['_id'])

        if not kv:
            return None
        
        return KeyVersionModel(**kv)
    
    async def list_keys_async(self, limit:int, cursor:Optional[int] = None) -> tuple[List[dict[str, Any]], Optional[int], bool]:
        rows = await self.repo.list_keys_async(limit,cursor)
        
        has_next = len(rows) > limit

        if has_next:
            rows = rows[:limit]

        next_ = rows[-1]["_id"] if rows else None
        return rows, next_, has_next
    
    def list_keys_sync(self, limit:int, cursor:Optional[int] = None) -> tuple[List[dict[str, Any]], Optional[int], bool]:
        rows = self.repo.list_keys_sync(limit,cursor)
        
        has_next = len(rows) > limit

        if has_next:
            rows = rows[:limit]
        
        next_ = rows[-1]["_id"] if rows else None
        return rows, next_, has_next
    
    async def export_async(self, name:str, actor:str, version:Optional[int] = None) -> dict[str, Any]:
        lk = await self.repo.get_logical_key_by_name_async(name=name)

        if not lk or lk['exportable'] != 1:
            await self.audit.log_event_async(
                action="kms:export", actor=actor, status="DENIED",
                details={"logical_key": name, "reason": "Key is not flagged as exportable"}, ask=self.ask
            )
            raise PolicyDenialError(f"Access Denied: Key reference '{name}' is not configured for export extraction.")
        
        kv = None
        if version:
            kv = await self.repo.get_key_version_by_kid_async(kid=f"{name}:{version}")
        else:
            kv = await self.repo.get_active_version_for_logical_key_async(logical_key_id=lk['_id'])
        
        if not kv:
            raise KeyLifecycleError("Requested physical key version variant is unreachable.")
        
        wrapped_key = bytes.fromhex(kv['raw_material'])
        raw_material = decrypt_envelope(wrapped_key, self.rmk)

        wrapped_key = bytes.fromhex(kv['raw_material'])
        raw_material = decrypt_envelope(wrapped_key, self.rmk)
        
        dependencies = await self.repo.get_dependency_count_async(kid=kv['kid'])

        await self.audit.log_event_async(
            action="kms:export", actor=actor, status="SUCCESS",
            details={"kid": kv['kid']}, ask=self.ask
        )
        
        data= {
            "meta": {
                "kid": kv['kid'], "purpose": lk['purpose'],
                "algorithm": kv['algorithm'],
                "dependencies_count": dependencies
            },
            "key_hex": raw_material.hex(), 
        }

        if lk['description']:
            data['meta']['description'] = lk['description']
        
        return data
    
    def export_sync(self, name:str, actor:str, version:Optional[int] = None) -> dict[str, Any]:
        lk = self.repo.get_logical_key_by_name_sync(name=name)

        if not lk or lk['exportable'] != 1:
            self.audit.log_event_sync(
                action="kms:export", actor=actor, status="DENIED",
                details={"logical_key": name, "reason": "Key is not flagged as exportable"}, ask=self.ask
            )
            raise PolicyDenialError(f"Access Denied: Key reference '{name}' is not configured for export extraction.")
        
        kv = None
        if version:
            kv = self.repo.get_key_version_by_kid_sync(kid=f"{name}:{version}")
        else:
            kv = self.repo.get_active_version_for_logical_key_sync(logical_key_id=lk['_id'])
        
        if not kv:
            raise KeyLifecycleError("Requested physical key version variant is unreachable.")
        
        wrapped_key = bytes.fromhex(kv['raw_material'])
        raw_material = decrypt_envelope(wrapped_key, self.rmk)

        wrapped_key = bytes.fromhex(kv['raw_material'])
        raw_material = decrypt_envelope(wrapped_key, self.rmk)

        dependencies = self.repo.get_dependency_count_sync(kid=kv['kid'])

        self.audit.log_event_sync(
            action="kms:export", actor=actor, status="SUCCESS",
            details={"kid": kv['kid']}, ask=self.ask
        )
        
        data= {
            "meta": {
                "kid": kv['kid'], "purpose": lk['purpose'],
                "algorithm": kv['algorithm'],
                "dependencies_count": dependencies
            },
            "key_hex": raw_material.hex(), 
        }

        if lk['description']:
            data['meta']['description'] = lk['description']
        
        return data
    
    async def get_logical_key_async(self, logical_key_id:int) -> dict[str, Any]:
        lk = await self.repo.get_logical_key_by_id_async(id=logical_key_id)

        if not lk:
            raise KeyLifecycleError("Requested logical key is unreachable.")
        
        return lk

    def get_logical_key_sync(self, logical_key_id:int) -> dict[str, Any]:
        lk = self.repo.get_logical_key_by_id_sync(id=logical_key_id)

        if not lk:
            raise KeyLifecycleError("Requested logical key is unreachable.")
        
        return lk
    
    async def add_dependency_async(self, ciphertext_id: str, ref_kid: str, status: str) -> dict[str, Any]:
        return await self.repo.add_dependency_async(ciphertext_id, ref_kid, status)
    
    def add_dependency_sync(self, ciphertext_id: str, ref_kid: str, status: str) -> dict[str, Any]:
        return self.repo.add_dependency_sync(ciphertext_id, ref_kid, status)