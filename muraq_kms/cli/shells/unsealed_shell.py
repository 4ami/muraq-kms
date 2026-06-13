import time

from muraq_kms.cli.shells.base_shell import BaseKMSShell

from muraq_kms.cli.ui.ui import UI
from muraq_kms.cli.ui.widgets import Spinner

from muraq_kms.storage.config import StorageConfig

from muraq_kms.core.engine import CoreEngine


class MKMSUnsealedShell(BaseKMSShell):
    """
    Routed Context: This shell is only accessible once the engine is unsealed.
    Put all key management, encryption, decryption, and token operations here.
    """

    def __init__(self, config: StorageConfig, engine: CoreEngine) -> None:
        super().__init__(config, engine)
        self._session_start = time.time()
    
    def preloop(self) -> None:
        self.do_clear(None)
        dep_id = getattr(self.engine, 'deployment_id', None)
        deployment_id = str(dep_id) if dep_id else "UNKNOWN_DEPLOYMENT"
        uptime_delta = time.time() - self._session_start
        uptime = time.strftime("%H:%M:%S", time.gmtime(uptime_delta))
        inner_width = 66 

        # Build lines by calculating dynamic whitespace explicitly, ignoring invisible ANSI weights
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

        self.intro = f"""
{UI.COLORS.GREEN}╭────────────────────────────────────────────────────────────────────╮
│ {UI.ANSIESCAPE.BOLD}MURAQ-KMS RUNTIME LAYER [UNSEALED ENVIRONMENT]                     {UI.ANSIESCAPE.RESET}{UI.COLORS.GREEN}│
├────────────────────────────────────────────────────────────────────┤
{dep_line}
{uptime_line}
{lock_line}
╰────────────────────────────────────────────────────────────────────╯{UI.ANSIESCAPE.RESET}
Type {UI.COLORS.YELLOW}help{UI.COLORS.CYAN} or {UI.COLORS.YELLOW}?{UI.COLORS.CYAN} to look up active crypto operations.
""".strip()


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
        # if self.engine.state == EngineState.SEALED:
        #     print(f"{UI.STATUS.INFO} Engine is already sealed.")
        #     return

        with Spinner("Wiping volatile keys and zeroing transient execution cache memory buffers..."):
            self.engine.seal()
            time.sleep(0.4)
        print(f"{UI.STATUS.SUCCESS} Engine successfully isolated and sealed down.")
        return True

    def do_list_keys(self, arg: str) -> None:
        """
        lists keys.
        Usage: list, -ls
        """
        print(f"{UI.STATUS.INFO} Accessing decoupled active cryptographic keys...")

    def do_exit(self, arg: str) -> bool:
        with Spinner("Purging active workspace boundaries from volatile console process stack..."):
            self.engine.seal()
            time.sleep(0.3)
        print(f"{UI.STATUS.SUCCESS} Active shell process context safely disposed. Goodbye.")
        return True

    def do_EOF(self, arg: str) -> bool:
        print()
        return self.do_exit(arg)