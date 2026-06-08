import pytest
import os
from crypto.kdf import derive_pp_key

def test_kdf_derivation_is_deterministic(valid_passphrase, valid_salt):
    key_a = derive_pp_key(valid_passphrase, valid_salt)
    key_b = derive_pp_key(valid_passphrase, valid_salt)
    
    assert len(key_a) == 32
    assert key_a == key_b

def test_kdf_derivation_changes_with_salt(valid_passphrase, valid_salt):
    another_salt = os.urandom(16)
    key_a = derive_pp_key(valid_passphrase, valid_salt)
    key_b = derive_pp_key(valid_passphrase, another_salt)
    
    assert key_a != key_b

def test_kdf_derivation_changes_with_passphrase(valid_salt):
    key_a = derive_pp_key("PassphraseAlpha", valid_salt)
    key_b = derive_pp_key("PassphraseBeta", valid_salt)
    
    assert key_a != key_b

def test_kdf_rejects_insecure_salt_lengths(valid_passphrase):
    short_salt = b"too-short"
    with pytest.raises(ValueError, match="Insecure salt length"):
        derive_pp_key(valid_passphrase, short_salt)