import time
from typing import Optional

from muraq_kms.cli.shells.base_shell import BaseKMSShell

from muraq_kms.cli.services import RepairService

from muraq_kms.cli.shells.unsealed_shell import MKMSUnsealedShell

from muraq_kms.storage.config import StorageConfig

from muraq_kms.core.engine import CoreEngine, EngineState
from muraq_kms.core.doctor import DoctorEngine, DiagnosticReport

from muraq_kms.cli.services.init_service import init_kms
from muraq_kms.cli.services.unseal_service import unseal_kms

from muraq_kms.cli.ui.ui import UI
from muraq_kms.cli.ui.widgets import Frame, Spinner, SpinnerGroup

class MKMSShell(BaseKMSShell):
    intro = f"""
{UI.COLORS.CYAN}╭────────────────────────────────────────────────────────────────────╮
│ {UI.ANSIESCAPE.BOLD}Muraq KMS v1 Interactive Cryptographic Engine Shell                {UI.ANSIESCAPE.RESET}{UI.COLORS.CYAN}│
│ Type {UI.COLORS.YELLOW}help{UI.COLORS.CYAN} or {UI.COLORS.YELLOW}?{UI.COLORS.CYAN} to list commands, or {UI.COLORS.RED}exit{UI.COLORS.CYAN} to quit.                  │
╰────────────────────────────────────────────────────────────────────╯{UI.ANSIESCAPE.RESET}
    """

    def __init__(self, config: Optional[StorageConfig] = None) -> None:
        cfg = config or StorageConfig.from_env()
        eng = CoreEngine(cfg)
        super().__init__(cfg, eng)

    def _update_prompt(self) -> None:
        self.prompt = f"{UI.ANSIESCAPE.BOLD}muraq-kms{UI.ANSIESCAPE.RESET} {UI.COLORS.YELLOW}[SEALED]{UI.ANSIESCAPE.RESET} ❯ "

    def preloop(self) -> Optional[bool]:
        report: DiagnosticReport = DoctorEngine.diagnose(self.config)
        if report.is_healthy:
            return None

        with Frame("MURAQ-KMS HEALTH DIAGNOSTICS", color=UI.COLORS.RED) as f:
            for issue in report.issues:
                status = UI.STATUS.CRIT if issue.is_critical else UI.STATUS.WARN
                f.line(f"{status}{UI.ANSIESCAPE.BOLD}Asset:{UI.ANSIESCAPE.RESET} {issue.asset} {UI.ANSIESCAPE.DIM}❯{UI.ANSIESCAPE.RESET} {issue.message}")
        
        if report.has_critical:
            print(f"{UI.STATUS.CRIT}{UI.COLORS.RED}{UI.ANSIESCAPE.BOLD}FATAL UNUSABILITY ERROR:{UI.ANSIESCAPE.RESET} Critical infrastructure components missing/corrupted.")
            print("   System operations are locked down to protect active keys. Access Denied.\n")
            return True 
        
        print(f"{UI.STATUS.HINT}{UI.ANSIESCAPE.BOLD}NOTICE:{UI.ANSIESCAPE.RESET} Issues found are repairable. Run {UI.COLORS.CYAN}'fix'{UI.ANSIESCAPE.RESET} to restore schemas.\n")
        return None

    def do_init(self, arg: str) -> None:
        """
        Initializes the local appliance deployment state.
        Usage: init [--force]
        """

        if "--force" in arg or "-f" in arg:
            confirm = UI.ask_yes_no("Are you absolutely sure you want to FORCE re-initialization?", default=False)
            if not confirm:
                print(f"{UI.STATUS.INFO} Initialization aborted by user.")
                return
        
        with SpinnerGroup("Appliance Initialization Pipeline") as sg:
            sg.run_step("Evaluating environment variables...", time.sleep, 0.2)
            sg.run_step("Deploying localized appliance state configuration...", init_kms, self.config, arg)

    def do_doctor(self, arg: str) -> None:
        """
        Run complete physical health preflight checks across system files and storage databases.
        Usage: doctor
        """
        report: DiagnosticReport = DoctorEngine.diagnose(self.config)
        if report.is_healthy:
            print(f"{UI.STATUS.SUCCESS} All systems operational. Components verified completely green.")
            return

        print(f"{UI.STATUS.FAIL} System anomalies detected: {UI.COLORS.RED}{len(report.issues)}{UI.ANSIESCAPE.RESET} item(s) need attention.\n")
        with Frame("System Diagnostic Summary", color=UI.COLORS.YELLOW) as f:
            for issue in report.issues:
                level = f"{UI.STATUS.CRIT}{UI.COLORS.RED}[CRITICAL]" if issue.is_critical else f"{UI.STATUS.WARN}{UI.COLORS.YELLOW}[WARNING]"
                f.line(f"{level}{UI.ANSIESCAPE.RESET} {UI.ANSIESCAPE.BOLD}{issue.asset}{UI.ANSIESCAPE.RESET}: {issue.message}")
        print(f"\n{UI.STATUS.HINT} Recommendations: Run the {UI.COLORS.CYAN}'fix'{UI.ANSIESCAPE.RESET} command.")
    
    def do_fix(self, arg: str) -> None:
        """
        Automatically repair broken schemas, missing directories, or corrupted tracking structures.
        Usage: fix
        """
        if not DoctorEngine.is_system_initialized(self.config):
            print(f"\n{UI.STATUS.FAIL} Refusing Repair: System has not been initialized yet.")
            print(f"{UI.STATUS.HINT} Please run the {UI.COLORS.CYAN}'init'{UI.ANSIESCAPE.RESET} command first to deploy your KMS instance safely.\n")
            return
        
        with SpinnerGroup("System Architecture Repair Service") as sg:
            sg.run_step("Analyzing local layout discrepancies...", time.sleep, 0.3)
            sg.run_step("Executing tracking schema validation...", RepairService.execute_repairs, self.config, self.engine.deployment_id)
        
    def do_unseal(self, arg: str) -> None:
        """
        Unlocks volatile memory structures and reconstitutes core secrets.
        Usage: unseal
        """
        if not DoctorEngine.is_system_initialized(self.config):
            print(f"\n{UI.STATUS.FAIL} Unseal Blocked: Infrastructure state absent.")
            
            with Frame("DEPLOYMENT INITIALIZATION REQUIRED", color=UI.COLORS.YELLOW) as f:
                f.line(f"The local appliance backend has not been deployed on this host yet.")
                f.line(f"Cryptographic storage matrices and key rings cannot be reconstitued")
                f.line(f"until the primary operational environment is securely anchored.")
                
            print(f"\n{UI.STATUS.HINT} Action Required: Execute the {UI.COLORS.CYAN}'init'{UI.ANSIESCAPE.RESET} command to provision your instance.\n")
            return
        
        print(f"{UI.STATUS.INFO} Initializing cryptographic unseal protocol...")
        UI.frame_header("Reconstituting volatile shards and core memory matrices...")
        unseal_kms(self.engine)
        if self.engine.state != EngineState.UNSEALED:
            print(f"{UI.STATUS.FAIL} Unseal protocol aborted: Engine remains in a sealed state.")
            return

        print(f"{UI.STATUS.SUCCESS} Engine unsealed successfully. Routing to active shell runtime...\n")
        
        sub_shell = MKMSUnsealedShell(self.config, self.engine)
        sub_shell.cmdloop()
        
        print(f"\n{UI.STATUS.INFO} Returned to root system administration layer.")

    def do_exit(self, arg: str) -> bool:
        with Spinner("Purging active workspace boundaries from console process stack..."):
            self.engine.seal()
            time.sleep(0.3)
        print(f"{UI.STATUS.SUCCESS} Active shell process context safely disposed. Goodbye.")
        return True

    def do_EOF(self, arg: str) -> bool:
        print()
        return self.do_exit(arg)