import time
import ctypes
from typing import Generator
from contextlib import contextmanager

from muraq_kms.policies.policy_error import LeaseExpiredError

class EphemeralKeyLease:
    """
    Manages an explicit short-lived lease wrapper over raw key objects.
    Implements mandatory zeroization hooks upon context destruction.
    """

    def __init__(self, key_id:str, raw_bytes:bytes, ttl_seconds:int) -> None:
        self.key_id = key_id
        self._buffer:bytearray = bytearray(raw_bytes)
        self._expires_at:float = time.time() + ttl_seconds
        self._invalidated:bool = False
    
    @property
    def key_material(self) -> bytes:
        if self._invalidated or time.time() > self._expires_at:
            self.zeroize()
            raise LeaseExpiredError(f"Security Timeout: Ephemeral lease for '{self.key_id}' has expired.")
        return bytes(self._buffer)
    
    def zeroize(self) -> None:
        if not self._invalidated:
            for i in range(len(self._buffer)):
                self._buffer[i] = 0
            self._invalidated = True

@contextmanager
def borrow_key_context(key_id:str, raw_bytes:bytes, ttl_seconds:int) -> Generator[EphemeralKeyLease, None, None]:
    lease = EphemeralKeyLease(key_id, raw_bytes, ttl_seconds)
    try:
        yield lease
    finally:
        lease.zeroize()
