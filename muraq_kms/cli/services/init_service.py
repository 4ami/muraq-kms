import shlex

from typing import Optional

from getpass import getpass

from muraq_kms.storage.config import StorageConfig
from muraq_kms.core.bootstrap import bootstrap
from muraq_kms.preflight.health import HealthPreFlight
from muraq_kms.cli.args import InitArgs



def preflight_testing() -> bool:
    print("[*] Launching dynamic suite self-tests to ensure code integrity...")
    health = HealthPreFlight()
    test_report = health.run_suite()

    print(f"[*] Executed {test_report['tests_run']} component tests.")
    if test_report["status"] != "PASSED":
        print("[-] Critical: Subsystem diagnostics failed. Aborting initialization sequence.")
        for detail in test_report["details"]:
            print(f"    -> {detail}")
        return False
    print("[+] Pre-flight engine code verification: PASSED.")
    return True


def idempotency_check(cfg:StorageConfig, force_flag:Optional[bool] = None) -> bool:
    manifest_path = cfg.base_dir / "manifest.json"
    drs_path = cfg.base_dir / "drs.enc"
    if (manifest_path.exists() or drs_path.exists()) and not force_flag:
        print("[-] Initialization Blocked: Deployment artifacts already exist.")
        print("[*] Hint: Use 'init --force' to clear and re-initialize the engine layout.")
        return False
    return True


def init_kms(config:StorageConfig, arg:str):
    args_list = shlex.split(arg)
    force = "--force" in args_list or "-f" in args_list

    init_args:InitArgs = InitArgs(force=force)

    if not preflight_testing():
        return
    
    if not idempotency_check(config, init_args.force):
        return

    try:
        config.ensure_layout()
    except PermissionError as pe:
        print(f"[-] Critical Error: Permission denied tracking root layout paths -> {pe}")
        return

    passphrase = ""
    while(True):
        passphrase = getpass("Enter master passphrase: ").strip()
        
        if passphrase in ("abort", "exit", "quit"):
            print("[-] Initialization Aborted by user.")
            return
        
        try:
            init_args.ensure_valid_passphrase(passphrase)

            confirm = getpass("Confirm master passphrase: ")
            if passphrase != confirm:
                print("[-] Initialization Error: Passphrases do not match. Restarting entry sequence...")
                print("-------------------------------------------------------------------------")
                continue
                
            break
        except ValueError as e:
            print(f"[-] Invalid Input: {e}")
            print("[*] Hint: Type 'abort', 'exit', or 'quit' to stop initialization and return to the main shell.")
            continue
        
    try:
        bootstrap(config=config, passphrase=passphrase, force=init_args.force)
        print("[+] Muraq KMS initialized successfully.")
        print(f"[+] Active operational workspace deployed cleanly to: {config.base_dir}")
    except Exception as e:
        print(f"[-] Critical Error encountered during bootstrap: {e}")