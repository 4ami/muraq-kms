import pytest
from crypto.primitives import split_root_secret

def test_secret_splitting_isolation(valid_drs, valid_deployment_salt):
    rmk, ask = split_root_secret(valid_drs, valid_deployment_salt)
    
    assert len(rmk) == 32
    assert len(ask) == 32
    
    assert rmk != ask
    assert rmk != valid_drs
    assert ask != valid_drs

def test_splitting_is_strictly_deterministic(valid_drs, valid_deployment_salt):
    rmk_1, ask_1 = split_root_secret(valid_drs, valid_deployment_salt)
    rmk_2, ask_2 = split_root_secret(valid_drs, valid_deployment_salt)
    
    assert rmk_1 == rmk_2
    assert ask_1 == ask_2

def test_splitting_rejects_weak_deployment_salts(valid_drs):
    weak_salt = b"weak"
    with pytest.raises(ValueError, match="Deployment salt must be"):
        split_root_secret(valid_drs, weak_salt)