import tempfile
from pathlib import Path
from muraq_kms.storage.config import StorageConfig

def test_config_enforces_isolated_subdirectory_on_bare_dot_input(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        monkeypatch.chdir(tmpdir)
        monkeypatch.setenv("MKMS_DATA_DIR", ".")
        
        config = StorageConfig.from_env()
        
        expected_root = Path(tmpdir).resolve() / ".muraq-kms"
        assert config.base_dir == expected_root
        assert config.db_path == expected_root / "keys.db"


def test_config_neutralizes_root_traversal_attempts(monkeypatch):
    monkeypatch.setenv("MKMS_DATA_DIR", "/")
    
    config = StorageConfig.from_env()
    
    assert config.base_dir == Path("/.muraq-kms")
    assert config.state_db_path == Path("/.muraq-kms/state.db")


def test_config_resolves_dot_dot_traversal_attacks(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        resolved_tmp = Path(tmpdir).resolve()
        levels = len(resolved_tmp.parts) + 2
        traversal_payload = "/".join(['..'] * levels)

        malicious_input = f"{resolved_tmp}/nested/dir/{traversal_payload}/etc"
        monkeypatch.setenv("MKMS_DATA_DIR", malicious_input)
        
        config = StorageConfig.from_env()
        
        resolved_etc = Path("/etc").resolve()
        assert config.base_dir == resolved_etc / ".muraq-kms"
        assert config.base_dir != resolved_etc


def test_ensure_layout_does_not_wipe_unrelated_files(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        base_path = Path(tmpdir).resolve()
        monkeypatch.setenv("MKMS_DATA_DIR", str(base_path))
        
        canary_file = base_path / "important_user_document.txt"
        canary_file.write_text("CRITICAL USER DATA", encoding="utf-8")
        
        config = StorageConfig.from_env()
        config.ensure_layout()
        
        assert config.base_dir.exists()
        assert config.base_dir.is_dir()
        assert config.base_dir.name == ".muraq-kms"
        
        assert canary_file.exists()
        assert canary_file.read_text(encoding="utf-8") == "CRITICAL USER DATA"