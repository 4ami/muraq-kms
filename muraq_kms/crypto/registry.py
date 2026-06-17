from muraq_kms.crypto.primitives import generate_secure_bytes

from enum import Enum
from typing import Dict, Callable, List, NamedTuple
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class AlgorithmType(str, Enum):
    SYMMETRIC = "symmetric"
    ASYMMETRIC = "asymmetric"

class AlgorithmSpec(NamedTuple):
    name: str
    type: AlgorithmType
    description: str
    generator_func: Callable[[], bytes]

def generate_symmetric_32b() -> bytes:
    return generate_secure_bytes()

def generate_rsa_2048()->bytes:
    pk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return pk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def generate_rsa_4096()->bytes:
    pk = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    return pk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


_REGISTRY:Dict[str, AlgorithmSpec] = {
    "XCHACHA20": AlgorithmSpec(
        name="XChaCha20",
        type=AlgorithmType.SYMMETRIC,
        description="Symmetric 256-bit stream cipher via PyNaCl/Libsodium.",
        generator_func=generate_symmetric_32b
    ),
    "AES256": AlgorithmSpec(
        name="AES256",
        type=AlgorithmType.SYMMETRIC,
        description="Advanced Encryption Standard with a 256-bit key length.",
        generator_func=generate_symmetric_32b
    ),
    "RS256": AlgorithmSpec(
        name="RS256",
        type=AlgorithmType.ASYMMETRIC,
        description="RSA 2048-bit key pair serialized into unencrypted PKCS8 PEM bytes.",
        generator_func=generate_rsa_2048
    ),
    "RS512": AlgorithmSpec(
        name="RS512",
        type=AlgorithmType.ASYMMETRIC,
        description="RSA 4096-bit key pair serialized into unencrypted PKCS8 PEM bytes.",
        generator_func=generate_rsa_4096
    ),
}

class MuraqKMSAlgorithms:
    CODES:List[str] = list(_REGISTRY.keys())
    SYMMETRIC_CODES:List[str] = [k for k, v in _REGISTRY.items() if v.type == AlgorithmType.SYMMETRIC]
    ASYMMETRIC_CODES:List[str] = [k for k, v in _REGISTRY.items() if v.type == AlgorithmType.ASYMMETRIC]

    class symmetric:
        XCHACHA20 = "XCHACHA20"
        AES256 = "AES256"

    class asymmetric:
        RS256 = "RS256"
        RS512 = "RS512"
    
    @classmethod
    def get_spec(cls, code:str) -> AlgorithmSpec:
        normalized = code.upper().strip()
        if normalized not in _REGISTRY:
            raise ValueError(f"Unsupported algorithm '{code}'. Supported types are: {cls.CODES}")
        return _REGISTRY[normalized]