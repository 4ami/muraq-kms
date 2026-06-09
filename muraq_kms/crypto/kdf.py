from argon2 import low_level

TIME_COST:int = 4
MEMORY_COST:int = 65536
PARALLELISM:int = 4
KEY_LEN:int = 32

def derive_pp_key(passphrase:str, salt:bytes) -> bytes:
    if len(salt) < 16:
        raise ValueError("Insecure salt length")
    
    return low_level.hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=TIME_COST,
        memory_cost=MEMORY_COST,
        parallelism=PARALLELISM,
        hash_len=KEY_LEN,
        type=low_level.Type.ID,
    )