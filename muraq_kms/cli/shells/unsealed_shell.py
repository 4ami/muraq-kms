import time
import argparse

from muraq_kms.cli.shells.base_shell import BaseKMSShell

from muraq_kms.cli.ui.ui import UI
from muraq_kms.cli.ui.widgets import Spinner, Frame

from muraq_kms.storage.config import StorageConfig
from muraq_kms.storage.pool import StoragePool

from muraq_kms.core.engine import CoreEngine

from muraq_kms.audit.manager import AuditManager
from muraq_kms.keys.manager import KeyManager

from muraq_kms.core.actor import cli_actor
from muraq_kms.crypto.registry import MuraqKMSAlgorithms

from muraq_kms.policies.models import KeyAccessPolicy

class MKMSUnsealedShell(BaseKMSShell):
    """
    Routed Context: This shell is only accessible once the engine is unsealed.
    Put all key management, encryption, decryption, and token operations here.
    """
    _header = f"""{UI.COLORS.GREEN}╭────────────────────────────────────────────────────────────────────╮
│ {UI.ANSIESCAPE.BOLD}MURAQ-KMS RUNTIME LAYER [UNSEALED ENVIRONMENT]                     {UI.ANSIESCAPE.RESET}{UI.COLORS.GREEN}│
├────────────────────────────────────────────────────────────────────┤"""

    _footer = f"""╰────────────────────────────────────────────────────────────────────╯{UI.ANSIESCAPE.RESET}
Type {UI.COLORS.YELLOW}help{UI.COLORS.CYAN} or {UI.COLORS.YELLOW}?{UI.COLORS.CYAN} to look up active crypto operations."""

    def __init__(self, config: StorageConfig, engine: CoreEngine) -> None:
        super().__init__(config, engine)
        self._session_start = time.time()

        pool = StoragePool(config)

        self.audit_manager = AuditManager(pool)
        self.key_manager = KeyManager(
            pool= pool,
            audit_manager= self.audit_manager,
            ask=self.engine.get_ask(),
            rmk=self.engine.get_rmk()
        )

        self._actor = cli_actor()
    
    def _intro_builder(self) -> tuple[str,...]:
        dep_id = getattr(self.engine, 'deployment_id', None)
        deployment_id = str(dep_id) if dep_id else "UNKNOWN_DEPLOYMENT"
        self._uptime_delta = time.time() - self._session_start
        uptime = time.strftime("%H:%M:%S", time.gmtime(self._uptime_delta))
        inner_width = 66 

        dep_line = f"│ {UI.ANSIESCAPE.DIM}Deployment ID:{UI.ANSIESCAPE.RESET} {deployment_id}"
        dep_padding = inner_width - (len("Deployment ID: ") + len(deployment_id))
        dep_line += (" " * dep_padding) + " │"

        uptime_line = f"│ {UI.ANSIESCAPE.DIM}Session Time :{UI.ANSIESCAPE.RESET} {uptime}"
        uptime_padding = inner_width - (len("Session Time : ") + len(uptime))
        uptime_line += (" " * uptime_padding) + " │"

        lock_str = "MEM_RESIDENT (EPHEMERAL)"
        lock_line = f"│ {UI.ANSIESCAPE.DIM}Volatile Lock:{UI.ANSIESCAPE.RESET} {lock_str}"
        lock_padding = inner_width - (len("Volatile Lock: ") + len(lock_str))
        lock_line += (" " * lock_padding) + " │"

        return (dep_line, uptime_line, lock_line)

    def preloop(self) -> None:
        self.do_clear(None)

        intro = f"{self._header}\n"
        lines = self._intro_builder()
        for l in lines:
            intro += f"{l}\n"
        intro += self._footer
        self.intro = intro

    def precmd(self, line: str) -> str:
        self.do_clear(None)

        intro = f"{self._header}\n"
        lines = self._intro_builder()
        for l in lines:
            intro += f"{l}\n"
        intro += self._footer
        self.intro = intro
        return line
#         self.intro = f"""
# {UI.COLORS.GREEN}╭────────────────────────────────────────────────────────────────────╮
# │ {UI.ANSIESCAPE.BOLD}MURAQ-KMS RUNTIME LAYER [UNSEALED ENVIRONMENT]                     {UI.ANSIESCAPE.RESET}{UI.COLORS.GREEN}│
# ├────────────────────────────────────────────────────────────────────┤
# {dep_line}
# {uptime_line}
# {lock_line}
# ╰────────────────────────────────────────────────────────────────────╯{UI.ANSIESCAPE.RESET}
# Type {UI.COLORS.YELLOW}help{UI.COLORS.CYAN} or {UI.COLORS.YELLOW}?{UI.COLORS.CYAN} to look up active crypto operations.
# """.strip()


    def _update_prompt(self) -> None:
        dep_id = getattr(self.engine, 'deployment_id', None)
        deployment_id = str(dep_id)[9:17] if dep_id else f"{'#'*10}"
        
        self.prompt = (
            f"{UI.ANSIESCAPE.BOLD}muraq-kms{UI.ANSIESCAPE.RESET} "
            f"({UI.COLORS.CYAN}{deployment_id}{UI.ANSIESCAPE.RESET}) "
            f"{UI.COLORS.GREEN}[UNSEALED]{UI.ANSIESCAPE.RESET} ❯ "
        )

    def do_seal(self, arg:str) -> None:
        """
        Purges memory registers and locks the engine down immediately.
        Usage: seal
        """
        with Spinner("Wiping volatile keys and zeroing transient execution cache memory buffers..."):
            self.engine.seal()
            time.sleep(0.4)
        print(f"{UI.STATUS.SUCCESS} Engine successfully isolated and sealed down.")
        return True
    
    def do_algorithms(self, arg:str) -> None:
        """
        Displays a structured layout of all active cryptographic engines and primitives.
        Usage: algorithms
        """
        with Frame(title=" MURAQ-KMS SUPPORTED CRYPTOGRAPHIC ALGORITHMS ", color=UI.COLORS.BLUE) as frame:
            frame.line(f"{UI.COLORS.CYAN}{UI.ANSIESCAPE.BOLD}[ SYMMETRIC PRIMITIVES ]{UI.ANSIESCAPE.RESET}")
            for code in MuraqKMSAlgorithms.SYMMETRIC_CODES:
                spec = MuraqKMSAlgorithms.get_spec(code)
                frame.line(f"💡 {UI.COLORS.YELLOW}{code}{UI.ANSIESCAPE.RESET} — {spec.description}")
            
            frame.line("")
            
            frame.line(f"{UI.COLORS.CYAN}{UI.ANSIESCAPE.BOLD}[ ASYMMETRIC SCHEMES ]{UI.ANSIESCAPE.RESET}")
            for code in MuraqKMSAlgorithms.ASYMMETRIC_CODES:
                spec = MuraqKMSAlgorithms.get_spec(code)
                frame.line(f"💡 {UI.COLORS.YELLOW}{code}{UI.ANSIESCAPE.RESET} — {spec.description}")
            
            frame.line("")
            
            frame.line(
                f"✔ {UI.ANSIESCAPE.DIM}To generate any engine spec layer variant above, execute: "
                f"{UI.COLORS.GREEN}create_key <name> <ALGORITHM_CODE>{UI.ANSIESCAPE.RESET}"
            )

    def do_create_key(self, arg:str) -> None:
        """
        Creates a new logical cryptographic key container with explicit access policies.
        Usage: create_key <key_name> <algorithm> --purpose <encryption|signing|wrapping> [--export] [--borrow] [--ttl <seconds>]
        Example: create_key order-signing-key RS256 --purpose signing --borrow --ttl 60
        """
        parser = argparse.ArgumentParser(prog="create_key", add_help=False, exit_on_error=False)
        parser.add_argument("name", help="Unique logical key identifier name.")
        parser.add_argument("algorithm", help="Cryptographic specification code (e.g., AES256, RS256).")
        parser.add_argument(
            "--purpose", required=True, choices=["encryption", "signing", "wrapping"],
            help="Designated business usage function of raw key material assets."
        )
        parser.add_argument("--export", action="store_true", help="Enable permanent raw material extraction.")
        parser.add_argument("--borrow", action="store_true", help="Enable temporary scoped leasing.")
        parser.add_argument("--ttl", type=int, default=30, help="Enforced maximum lifespan of an ephemeral key lease.")

        tokens = arg.strip().split()
        if not tokens:
            print(f"{UI.STATUS.FAIL} Operational error: Key identifier name argument is missing.")
            return
        
        try:
            parsed_args = parser.parse_args(tokens)
        except (argparse.ArgumentError, TypeError) as parse_err:
            print(f"{UI.STATUS.FAIL} Syntax Error: {str(parse_err)}")
            return
        
        try:
            spec = MuraqKMSAlgorithms.get_spec(parsed_args.algorithm)
        except ValueError as algo_err:
            print(f"{UI.STATUS.FAIL} Cryptographic Constraint Violation: {str(algo_err)}")
            return

        try:
            policy = KeyAccessPolicy(
                export=parsed_args.export,
                borrow=parsed_args.borrow,
                borrow_ttl_seconds=parsed_args.ttl
            )
        except Exception as policy_error:
            print(f"{UI.STATUS.FAIL} Policy Validation Error: {str(policy_error).splitlines()[0]}")
            return

        try:
            with Spinner(f"Generating cryptographically sound {spec.name} material primitives for '{parsed_args.name}'..."):
                 model = self.key_manager.create_key_sync(
                    actor=self._actor, 
                    name=parsed_args.name, 
                    purpose=parsed_args.purpose, 
                    algorithm=spec.name,
                    policy=policy
                )
            print(f"{UI.STATUS.SUCCESS} Key version tracking container '{model.kid}' successfully generated.")

            print(f"   {UI.ANSIESCAPE.DIM}├─ Algorithm      : {spec.name} ({spec.type.upper()})")
            print(f"   ├─ Export Allowed : {policy.export}")
            print(f"   ├─ Borrow Scoped  : {policy.borrow}")
            print(f"   └─ Lease Window   : {policy.borrow_ttl_seconds}s{UI.ANSIESCAPE.RESET}\n")
        except Exception as e:
            print(f"{UI.STATUS.FAIL} Execution failed: {str(e)}")

    def do_borrow_key(self, arg: str) -> None:
        """
        Temporarily leases raw key material within an isolated runtime zeroization boundary.
        Usage: borrow_key <key_name> [version]
        Example: borrow_key microservice-auth-key 1
        """
        parser = argparse.ArgumentParser(prog="borrow_key", add_help=False, exit_on_error=False)
        parser.add_argument("name", help="Target unique logical key identifier name.")
        parser.add_argument("version", type=int, nargs="?", default=None, help="Optional version number.")

        tokens = arg.strip().split()
        if not tokens:
            print(f"{UI.STATUS.FAIL} Arguments missing. Usage: borrow_key <name> [version]")
            return

        try:
            parsed_args = parser.parse_args(tokens)
        except (argparse.ArgumentError, TypeError) as parse_err:
            print(f"{UI.STATUS.FAIL} Syntax Error: {str(parse_err)}")
            return

        try:
            borrow_ctx = self.key_manager.borrow_key_sync(
                actor=self._actor,
                name=parsed_args.name,
                version=parsed_args.version
            )
            
            print(f"{UI.STATUS.INFO} Requesting secure execution lease allocation segment...")
            
            with borrow_ctx as lease:
                print(f"{UI.STATUS.SUCCESS} Ephemeral cryptographic lease successfully activated.")
                print(f"   {UI.ANSIESCAPE.DIM}├─ Lease Handle KeyID : {lease.key_id}")
                print(f"   ├─ Memory Address   : {hex(id(lease.key_material))}")
                print(f"   ├─ RAW KEY MATERIAL : {UI.COLORS.YELLOW}{lease.key_material.hex()}{UI.ANSIESCAPE.RESET}")
                print(f"   └─ Lifespan Window  : Active inside this terminal context{UI.ANSIESCAPE.RESET}")

                time.sleep(lease.ttl_seconds)
                self.do_clear(None)
            print(f"{UI.STATUS.SUCCESS} Lease expired. Volatile transient memory registers zeroed out successfully.")

        except Exception as e:
            print(f"{UI.STATUS.FAIL} Lease Request Refused: {str(e)}")

    def do_keys(self, arg: str) -> None:
        """
        lists keys.
        Usage: list, -ls
        """
        print(f"{UI.STATUS.INFO} Accessing decoupled active cryptographic keys...")

    def do_logs(self, arg: str) -> None:
        """
        Monitors runtime append-only cryptographic log audit trails with integrity checking.
        Usage: logs [--limit <count>] [--verify]
        Example: logs --limit 10 --verify
        """
        parser = argparse.ArgumentParser(prog="logs", add_help=False, exit_on_error=False)
        parser.add_argument("--limit", type=int, default=20, help="Number of records to fetch.")
        parser.add_argument("--verify", action="store_true", help="Perform real-time HMAC chain integrity scan.")

        try:
            parsed_args = parser.parse_args(arg.strip().split())
        except (argparse.ArgumentError, TypeError) as parse_err:
            print(f"{UI.STATUS.FAIL} Syntax Error: {str(parse_err)}")
            return

        if not self.audit_manager.repo:
            print(f"{UI.STATUS.FAIL} Error: Audit log repository pipeline initialization missing.")
            return

        if parsed_args.verify:
            with Spinner("Scanning append-only cryptographic ledger sequence hashes..."):
                try:
                    self.audit_manager.verify_chain_integrity_sync(self.ask)
                    print(f"{UI.STATUS.SUCCESS} Verification Passed: Cryptographic backlink history matches pristine runtime state.")
                except Exception as integrity_err:
                    print(f"{UI.STATUS.FAIL} SECURITY ALARM: {str(integrity_err)}")
                    return
        try:
            rows = self.audit_manager.repo.all_sync()
            display_rows = rows[:parsed_args.limit]
        except Exception as db_err:
            print(f"{UI.STATUS.FAIL} Failed to read database log rows: {str(db_err)}")
            return

        if not display_rows:
            print(f"{UI.STATUS.INFO} Audit ledger history contains no entries yet.")
            return

        with Frame(title=f" MURAQ-KMS IMMUTABLE AUDIT TRAIL (Last {len(display_rows)} Events) ", color=UI.COLORS.CYAN) as frame:
            for row in display_rows:

                from datetime import datetime, timezone
                dt_str = datetime.fromtimestamp(float(row[0]), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                
                status_color = UI.COLORS.GREEN if row[4] == "SUCCESS" else UI.COLORS.RED
                status_indicator = "✔" if row[4] == "SUCCESS" else "✗"
                
                header_line = f"[{dt_str}] ID: {row[7]} — {UI.ANSIESCAPE.BOLD}{row[1]}{UI.ANSIESCAPE.RESET}"
                meta_line = f"   Actor : {UI.COLORS.YELLOW}{row[2]}{UI.ANSIESCAPE.RESET} | Status: {status_color}{status_indicator} {row[4]}{UI.ANSIESCAPE.RESET}"
                payload_line = f"   Payload: {UI.ANSIESCAPE.DIM}{row[3]}{UI.ANSIESCAPE.RESET}"
                hash_line = f"   Signature: {UI.ANSIESCAPE.DIM}{str(row[6])[:16]}...{UI.ANSIESCAPE.RESET}"
                
                frame.line(header_line)
                frame.line(meta_line)
                frame.line(payload_line)
                frame.line(hash_line)
                frame.line("—" * 60)

    def do_exit(self, arg: str) -> bool:
        with Spinner("Purging active workspace boundaries from volatile console process stack..."):
            self.engine.seal()
            time.sleep(0.3)
        print(f"{UI.STATUS.SUCCESS} Active shell process context safely disposed. Goodbye.")
        return True

    def do_EOF(self, arg: str) -> bool:
        print()
        return self.do_exit(arg)