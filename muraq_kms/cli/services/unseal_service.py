from getpass import getpass
import json
from pathlib import Path

from muraq_kms.core.engine import CoreEngine, EngineState
from muraq_kms.core.exceptions import EngineError
from muraq_kms.core.throttling import ThrottlingEngine

from muraq_kms.cli.ui.ui import UI
from muraq_kms.cli.ui.widgets import Frame, Spinner

from typing import Optional

def get_deployment_id(manifest:Path) -> Optional[str]:
    try:
        with open(manifest, "r", encoding="utf-8") as m:
            manifest_data = json.load(m)
        return manifest_data["deployment_id"]
    except Exception as e:
        print(f"{UI.STATUS.CRIT}{UI.COLORS.RED}Critical Error:{UI.ANSIESCAPE.RESET} Manifest layout unreadable -> {e}")
        return None

def unseal_kms(engine:CoreEngine) -> None:
    if engine.state == EngineState.UNSEALED:
        print(f"{UI.STATUS.INFO} Engine is already unsealed and operating normally.")
        return
    
    manifest_path = engine.config.base_dir / "manifest.json"
    drs_path = engine.config.base_dir / "drs.enc"
    sig_path = engine.config.base_dir / "signature.enc"
    if not manifest_path.exists() or not drs_path.exists() or not sig_path.exists():
        print(f"{UI.STATUS.FAIL} Unseal Blocked: This appliance space has not been initialized yet.")
        print(f"{UI.STATUS.HINT} If {UI.COLORS.RED}signature.enc{UI.ANSIESCAPE.RESET} was deleted, the deployment context is permanently unrecoverable.")
        print(f"{UI.STATUS.HINT} Run the {UI.COLORS.CYAN}'init'{UI.ANSIESCAPE.RESET} command to create a brand new deployment first.")
        return

    deployment_id = get_deployment_id(manifest_path)
    if not deployment_id:
        return

    throttler = ThrottlingEngine(config=engine.config, deployment_id=deployment_id)
    status = throttler.check_status()

    if status.was_tampered:
        with Frame("SECURITY ALTERCATION DETECTED", color=UI.COLORS.RED) as f:
            f.line(f"{UI.STATUS.CRIT} Engine state anomalies or validation failure detected!")
            f.line(f"{UI.STATUS.WARN} Recovering system file layouts and enforcing defensive safety cooldown...")
        throttler.enforce_tamper_lockout()
        print(f"{UI.STATUS.FAIL} System Restabilized: Access temporarily throttled for 30 minutes to protect key blocks.")
        return
    
    if status.is_locked:
        remaining_minutes = int(status.remaining_seconds / 60) + 1
        print(f"{UI.STATUS.FAIL} Access Refused: The cryptographic boundary is locked due to security incidents.")
        print(f"{UI.STATUS.CRIT} Engine unavailable. Please try again in approximately {UI.COLORS.RED}{remaining_minutes} minute(s){UI.ANSIESCAPE.RESET}.")
        return

    print(f"{UI.STATUS.WARN} Security clearance required. You have {UI.COLORS.YELLOW}{UI.ANSIESCAPE.BOLD}{status.remaining_attempts}{UI.ANSIESCAPE.RESET} attempt(s) remaining.")
    print(f"{UI.STATUS.HINT} Type {UI.COLORS.RED}abort{UI.ANSIESCAPE.RESET} at the prompt to cancel the workflow.\n")

    while True:
        dynamic_status = throttler.check_status()
        if dynamic_status.is_locked:
            print(f"{UI.STATUS.FAIL} Locked out...")
            return
        passphrase = getpass("Enter master passphrase: ").strip()
        
        if passphrase.lower() in ("abort", "exit", "quit"):
            print(f"{UI.STATUS.INFO} Unseal workflow cancelled.")
            return
        
        if not passphrase:
            print(f"{UI.STATUS.WARN} Unseal Aborted: Passphrase cannot be empty.")
            return

        with Spinner("Validating cryptographic authenticity matrices..."):
            try:
                engine.unseal(passphrase)
                success = True
                error_type = None
            except EngineError as ee:
                success = False
                error_type = "engine"
                error_message = str(ee)
            except Exception as e:
                success = False
                error_type = "systemic"
                error_message = str(e)

        if success:
            throttler.record_success()
            print(f"\n{UI.STATUS.SUCCESS} System Unsealed successfully.")
            print(f"{UI.STATUS.INFO} Active Deployment Footprint ID: {UI.COLORS.GREEN}{UI.ANSIESCAPE.BOLD}{engine.deployment_id}{UI.ANSIESCAPE.RESET}")
            return
        
        if error_type == "engine":
            if "CRITICAL" in error_message:
                print(f"\n{UI.STATUS.CRIT} {UI.COLORS.RED}{UI.ANSIESCAPE.BOLD}{error_message}{UI.ANSIESCAPE.RESET}")
                throttler.enforce_tamper_lockout()
                return
            post_failure_status = throttler.record_failure()
            if post_failure_status.is_locked:
                print(f"\n{UI.STATUS.CRIT} {UI.COLORS.RED}Critical: Maximum execution attempts reached.{UI.ANSIESCAPE.RESET}")
                print(f"{UI.STATUS.FAIL} Access Denied. Engine locked for the next 10 minutes.")
                return
            else:
                print(f"{UI.STATUS.FAIL} Verification Failed: Invalid passphrase. ({UI.COLORS.YELLOW}{post_failure_status.remaining_attempts}{UI.ANSIESCAPE.RESET} attempts left).\n")
        
        elif error_type == "systemic":
            print(f"{UI.STATUS.CRIT} Unexpected systemic breakdown during cryptographic extraction: {error_message}")
            return