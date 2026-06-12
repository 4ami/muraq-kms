import time
import cmd
from typing import Optional
import os

from muraq_kms.cli.services import RepairService
from muraq_kms.storage.config import StorageConfig

from muraq_kms.core.engine import CoreEngine, EngineState
from muraq_kms.core.doctor import DoctorEngine, DiagnosticReport

from muraq_kms.cli.services.init_service import init_kms
from muraq_kms.cli.services.unseal_service import unseal_kms

from muraq_kms.cli.ui.ui import UI
from muraq_kms.cli.ui.widgets import Frame, Spinner, SpinnerGroup

class MKMSShell(cmd.Cmd):
    intro = f"""
{UI.COLORS.CYAN}╭────────────────────────────────────────────────────────────────────╮
│ {UI.ANSIESCAPE.BOLD}Muraq KMS v1 Interactive Cryptographic Engine Shell                {UI.ANSIESCAPE.RESET}{UI.COLORS.CYAN}│
│ Type {UI.COLORS.YELLOW}help{UI.COLORS.CYAN} or {UI.COLORS.YELLOW}?{UI.COLORS.CYAN} to list commands, or {UI.COLORS.RED}exit{UI.COLORS.CYAN} to quit.                  │
╰────────────────────────────────────────────────────────────────────╯{UI.ANSIESCAPE.RESET}
    """
    prompt = f"{UI.ANSIESCAPE.BOLD}muraq-kms ❯ {UI.ANSIESCAPE.RESET}"

    def __init__(self, config: Optional[StorageConfig] = None) -> None:
        super().__init__()
        self.config = config or StorageConfig.from_env()
        self.engine = CoreEngine(self.config)
        self._update_prompt()

    def preloop(self) -> None:
        report:DiagnosticReport = DoctorEngine.diagnose(self.config)
        if not report.is_healthy:
            with Frame("MURAQ-KMS HEALTH DIAGNOSTICS", color=UI.COLORS.RED) as f:
                for issue in report.issues:
                    status = UI.STATUS.CRIT if issue.is_critical else UI.STATUS.WARN
                    f.line(f"{status}{UI.ANSIESCAPE.BOLD}Asset:{UI.ANSIESCAPE.RESET} {issue.asset} {UI.ANSIESCAPE.DIM}❯{UI.ANSIESCAPE.RESET} {issue.message}")
            
            if report.has_critical:
                print(f"{UI.STATUS.CRIT}{UI.COLORS.RED}{UI.ANSIESCAPE.BOLD}FATAL UNUSABILITY ERROR:{UI.ANSIESCAPE.RESET} Critical infrastructure components are missing or corrupted.")
                print(f"   System operations are locked down to protect active keys. Access Denied.\n")
                return True
            else:
                print(f"{UI.STATUS.HINT}{UI.ANSIESCAPE.BOLD}NOTICE:{UI.ANSIESCAPE.RESET} Issues found are repairable. Running the {UI.COLORS.CYAN}'fix'{UI.ANSIESCAPE.RESET} command can restore standard schemas.\n")
    
    def _update_prompt(self) -> None:
        if self.engine.state == EngineState.UNSEALED:
            state_str = f"{UI.COLORS.GREEN}[UNSEALED]{UI.ANSIESCAPE.RESET}"
        else:
            state_str = f"{UI.COLORS.YELLOW}[SEALED]{UI.ANSIESCAPE.RESET}"
        self.prompt = f"{UI.ANSIESCAPE.BOLD}muraq-kms{UI.ANSIESCAPE.RESET} {state_str} ❯{UI.ANSIESCAPE.RESET} "

    def postcmd(self, stop: bool, line: str) -> bool:
        self._update_prompt()
        return stop

    def do_init(self, arg: str) -> None:
        """
        Initializes the local appliance deployment state.
        Usage: init [--force]
        """
        if self.engine.state == EngineState.UNSEALED:
            print(f"{UI.STATUS.FAIL} Operation Blocked: Cannot initialize an active, unsealed engine.")
            print(f"{UI.STATUS.HINT} Run the {UI.COLORS.YELLOW}'seal'{UI.ANSIESCAPE.RESET} command first if you intend to purge data.")
            return
        
        if "--force" in arg or "-f" in arg:
            confirm = UI.ask_yes_no("Are you absolutely sure you want to FORCE re-initialization? This wipes active states.", default=False)
            if not confirm:
                print(f"{UI.STATUS.INFO} Initialization aborted by user.")
                return
        
        with SpinnerGroup("Appliance Initialization Pipeline") as sg:
            sg.run_step("Evaluating environment variables...", time.sleep, 0.2)
            sg.run_step("Deploying localized appliance state configuration...", init_kms, self.config, arg)

    def do_doctor(self, arg:str) -> None:
        """
        Run complete physical health preflight checks across system files and storage databases.
        Usage: doctor
        """
        report:DiagnosticReport = DoctorEngine.diagnose(self.config)
        
        if report.is_healthy:
            print(f"{UI.STATUS.SUCCESS} All systems operational. Components verified completely green.")
        else:
            print(f"{UI.STATUS.FAIL} System anomalies detected: {UI.COLORS.RED}{len(report.issues)}{UI.ANSIESCAPE.RESET} item(s) need attention.\n")
            
            with Frame("Systme Diagnostic Summary", color=UI.COLORS.YELLOW) as f:
                for issue in report.issues:
                    if issue.is_critical:
                        f.line(f"{UI.STATUS.CRIT}{UI.COLORS.RED}[CRITICAL]{UI.ANSIESCAPE.RESET} {UI.ANSIESCAPE.BOLD}{issue.asset}{UI.ANSIESCAPE.RESET}: {issue.message}")
                    else:
                        f.line(f"{UI.STATUS.WARN}{UI.COLORS.YELLOW}[WARNING]{UI.ANSIESCAPE.RESET} {UI.ANSIESCAPE.BOLD}{issue.asset}{UI.ANSIESCAPE.RESET}: {issue.message}")
            print(f"\n{UI.STATUS.HINT} Recommendations: Run the {UI.COLORS.CYAN}'fix'{UI.ANSIESCAPE.RESET} command to systematically repair anomalies.")
    
    def do_fix(self, arg:str) -> None:
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
            sg.run_step("Executing tracking schema validation and physical repairs...", RepairService.execute_repairs, self.config, self.engine.deployment_id)
        
    def do_unseal(self, arg:str) -> None:
        """
        Unlocks volatile memory structures and reconstitutes core secrets.
        Usage: unseal
        """
        if self.engine.state == EngineState.UNSEALED:
            print(f"{UI.STATUS.SUCCESS} Engine is already unsealed and actively operating.")
            return

        print(f"{UI.STATUS.INFO} Initializing cryptographic unseal protocol...")
        
        with Spinner("Reconstituting volatile shards and core memory matrices..."):
            unseal_kms(self.engine)
    
    def do_seal(self, arg:str) -> None:
        """
        Purges memory registers and locks the engine down immediately.
        Usage: seal
        """
        if self.engine.state == EngineState.SEALED:
            print(f"{UI.STATUS.INFO} Engine is already sealed.")
            return

        with Spinner("Wiping volatile keys and zeroing transient execution cache memory buffers..."):
            self.engine.seal()
            time.sleep(0.4)
        print(f"{UI.STATUS.SUCCESS} Engine successfully isolated and sealed down.")

    def do_exit(self, arg: str) -> bool:
        with Spinner("Purging active workspace boundaries from volatile console process stack..."):
            self.engine.seal()
            time.sleep(0.3)
        print(f"{UI.STATUS.SUCCESS} Active shell process context safely disposed. Goodbye.")
        return True

    def do_EOF(self, arg: str) -> bool:
        print()
        return self.do_exit(arg)

    def emptyline(self) -> None:
        pass

    def do_clear(self, arg: str) -> None:
        """
        Clears the terminal screen completely and restores the shell carriage.
        Usage: clear
        """
        os.system('cls' if os.name == 'nt' else 'clear') 
        print(self.intro)
        self._update_prompt()