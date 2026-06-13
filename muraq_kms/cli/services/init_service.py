import shlex

from typing import Optional

from getpass import getpass

from muraq_kms.storage.config import StorageConfig
from muraq_kms.core.bootstrap import bootstrap
from muraq_kms.preflight.health import HealthPreFlight
from muraq_kms.cli.args import InitArgs

from muraq_kms.cli.ui.ui import UI
from muraq_kms.cli.ui.widgets import Frame


def preflight_testing() -> bool:
    print(f" -> {UI.STATUS.INFO} Launching dynamic suite self-tests to ensure code integrity...")
    health = HealthPreFlight()
    test_report = health.run_suite()

    print(f" -> {UI.STATUS.INFO} Executed {UI.COLORS.CYAN}{test_report['tests_run']}{UI.ANSIESCAPE.RESET} component tests.")
    if test_report["status"] != "PASSED":
        print(f" -> {UI.STATUS.CRIT} {UI.COLORS.RED}{UI.ANSIESCAPE.BOLD}Critical:{UI.ANSIESCAPE.RESET} Subsystem diagnostics failed. Aborting initialization sequence.")
        for detail in test_report["details"]:
            print(f"    {UI.COLORS.RED}❯{UI.ANSIESCAPE.RESET} {detail}")
        return False
    print(f" -> {UI.STATUS.SUCCESS} Pre-flight engine code verification: {UI.COLORS.GREEN}PASSED{UI.ANSIESCAPE.RESET}.")
    return True


def idempotency_check(cfg:StorageConfig, force_flag:Optional[bool] = None) -> bool:
    manifest_path = cfg.base_dir / "manifest.json"
    drs_path = cfg.base_dir / "drs.enc"
    if (manifest_path.exists() or drs_path.exists()) and not force_flag:
        print(f" -> {UI.STATUS.FAIL} Initialization Blocked: Deployment artifacts already exist.")
        print(f" -> {UI.STATUS.HINT} Use {UI.COLORS.CYAN}'init --force'{UI.ANSIESCAPE.RESET} to clear and re-initialize the engine layout.")
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
        print(f" -> {UI.STATUS.CRIT} {UI.COLORS.RED}Critical Error:{UI.ANSIESCAPE.RESET} Permission denied tracking root layout paths -> {pe}")
        return

    passphrase = ""
    print(f"\n{UI.STATUS.INFO} Secure credential creation sequence initiated.")
    print(f"{UI.STATUS.HINT} Type {UI.COLORS.RED}abort{UI.ANSIESCAPE.RESET} at any time to cancel initialization.\n")
    while(True):
        passphrase = getpass("\nEnter master passphrase: ").strip()
        
        if passphrase in ("abort", "exit", "quit"):
            print(f"{UI.STATUS.INFO} Initialization aborted by user.")
            return
        
        try:
            init_args.ensure_valid_passphrase(passphrase)

            confirm = getpass("Confirm master passphrase: ")
            if passphrase != confirm:
                print(f"{UI.STATUS.FAIL} {UI.COLORS.RED}Initialization Error:{UI.ANSIESCAPE.RESET} Passphrases do not match. Restarting entry sequence...\n")
                continue
                
            break
        except ValueError as e:
            print(f"{UI.STATUS.WARN} {UI.COLORS.YELLOW}Invalid Input:{UI.ANSIESCAPE.RESET} {e}\n")
            continue
        
    try:
        bootstrap(config=config, passphrase=passphrase, force=init_args.force)
        print(f"\n{UI.STATUS.SUCCESS} {UI.COLORS.GREEN}{UI.ANSIESCAPE.BOLD}Muraq KMS initialized successfully.{UI.ANSIESCAPE.RESET}")
        print(f"{UI.STATUS.INFO} Active operational workspace deployed cleanly to: {UI.COLORS.CYAN}{config.base_dir}{UI.ANSIESCAPE.RESET}")
    except Exception as e:
        print(f"\n{UI.STATUS.CRIT} {UI.COLORS.RED}Critical Error encountered during bootstrap:{UI.ANSIESCAPE.RESET} {e}")