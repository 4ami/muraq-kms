from getpass import getpass
import json
from pathlib import Path

from muraq_kms.core.engine import CoreEngine, EngineState
from muraq_kms.core.exceptions import EngineError
from muraq_kms.core.throttling import ThrottleStatus, ThrottlingEngine

from typing import Optional

def get_deployment_id(manifest:Path) -> Optional[str]:
    try:
        with open(manifest, "r", encoding="utf-8") as m:
            manifest_data = json.load(m)
        return manifest_data["deployment_id"]
    except Exception as e:
        print(f"[-] Critical Error: Manifest layout unreadable -> {e}")
        return None

def unseal_kms(engine:CoreEngine) -> None:
    if engine.state == EngineState.UNSEALED:
        print("[*] Engine is already unsealed and operating normally.")
        return
    
    manifest_path = engine.config.base_dir / "manifest.json"
    drs_path = engine.config.base_dir / "drs.enc"
    sig_path = engine.config.base_dir / "signature.enc"
    if not manifest_path.exists() or not drs_path.exists() or not sig_path.exists():
        print("[-] Unseal Blocked: This appliance space has not been initialized yet.")
        print("[*] Hint: If signature.enc was deleted, the system deployment context is permanently unrecoverable.")
        print("[*] Hint: Run the 'init' command to create a brand new deployment first.")
        return

    deployment_id = get_deployment_id(manifest_path)
    if not deployment_id:
        return

    throttler = ThrottlingEngine(config=engine.config, deployment_id=deployment_id)
    status = throttler.check_status()

    if status.was_tampered:
        print("[-] SECURITY WARNING: Engine state anomalies or validation failure detected!")
        print("[!] Recovering system file layouts and enforcing defensive safety cooldown...")
        throttler.enforce_tamper_lockout()
        print("[-] System Restabilized: Access temporarily throttled for 30 minutes to protect key blocks.")
        return
    
    if status.is_locked:
        remaining_minutes = int(status.remaining_seconds / 60) + 1
        print(f"[-] Access Refused: The cryptographic boundary is locked due to security incidents.")
        print(f"[!] Engine unavailable. Please try again in approximately {remaining_minutes} minute(s).")
        return

    print(f"[*] Security clearance required. You have {status.remaining_attempts} attempt(s) remaining.")

    while True:
        dynamic_status = throttler.check_status()
        if dynamic_status.is_locked:
            print("[-] Locked out...")
            return
        passphrase = getpass("Enter master passphrase: ").strip()
        
        if passphrase.lower() in ("abort", "exit", "quit"):
            print("[-] Unseal workflow cancelled.")
            return
        
        if not passphrase:
            print("[-] Unseal Aborted: Passphrase cannot be empty.")
            return
    
        print("[*] Verifying...")

        try:
            engine.unseal(passphrase)
            throttler.record_success()
            print("[+] System Unsealed successfully.")
            print(f"[+] Active Deployment Footprint ID: {engine.deployment_id}")
            return
        except EngineError as ee:
            error_message = str(ee)
            if "CRITICAL" in error_message:
                print(f"\n🚨 {error_message}")
                throttler.enforce_tamper_lockout()
                return

            post_failure_status = throttler.record_failure()
            if post_failure_status.is_locked:
                print(f"\n[-] Critical: Maximum execution attempts reached.")
                print(f"[!] Access Denied. Engine locked for the next 10 minutes.")
                return
            else:
                print(f"[-] Verification Failed: Invalid passphrase. ({post_failure_status.remaining_attempts} attempts left).")
        except Exception as e:
            print(f"[-] Unexpected systemic breakdown during cryptographic extraction: {e}")
            return