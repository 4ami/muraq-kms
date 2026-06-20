import time
import shlex
from argparse import ArgumentError

from muraq_kms.cli.shells.base_shell import BaseKMSShell

from muraq_kms.cli.services.algorithms_service import list_algorithms

from muraq_kms.cli.ui.ui import UI
from muraq_kms.cli.ui.widgets import Spinner

from muraq_kms.storage.config import StorageConfig
from muraq_kms.storage.pool import StoragePool

from muraq_kms.core.engine import CoreEngine

from muraq_kms.audit.manager import AuditManager
from muraq_kms.keys.manager import KeyManager

from muraq_kms.core.actor import cli_actor

from muraq_kms.cli.services import key_services, audit_services
from muraq_kms.cli.args.key_args import build_key_parser
from muraq_kms.cli.args.audit_args import build_audit_parser


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

    _key_parser = build_key_parser()
    _audit_parser = build_audit_parser()

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
        list_algorithms()

    def do_key(self, args:str) -> None:
        """
        Unified cryptographic key management utility.
        Usage:
            key -create <name> <algorithm> --purpose {encryption,signing,wrapping} [--desc <text>] [--export] [--borrow] [--ttl <seconds>]
            key -v -name <key_name>
            key -b <key_name> [<version>]
            key -ls [-l <limit>]
            key -export <name> [-v <version>] [-f <format>] [-o <output>]
        """
        tokens = shlex.split(args.strip())
        if not tokens:
            print(f"{UI.STATUS.FAIL} Operational error: Key identifier name argument is missing.")
            return
        
        try:
            parsed_args = self._key_parser.parse_args(tokens)
        except (ArgumentError, TypeError) as parse_err:
            print(f"{UI.STATUS.FAIL} Syntax Error: {str(parse_err)}")
            return

        if parsed_args.operation == "-create":
            if not parsed_args.borrow and parsed_args.ttl is not None:
                print(f"{UI.STATUS.FAIL} Syntax Error: Cannot specify --ttl without enabling --borrow.")
                return
            
            if not parsed_args.borrow:
                parsed_args.ttl = 0
            elif parsed_args.ttl is None:
                parsed_args.ttl = 30

        dispatch = {
            "-export": lambda: key_services.handle_export(self.key_manager, self._actor, parsed_args),
            "-create": lambda: key_services.handle_create(self.key_manager, self._actor, parsed_args),
            "-v": lambda: key_services.handle_version(self.key_manager, parsed_args.name),
            "-b": lambda: key_services.handle_borrow(self.key_manager, self._actor, parsed_args.name, self.do_clear, parsed_args.version),
            "-ls": lambda: key_services.handle_list(self.key_manager, parsed_args),
        }

        handler = dispatch.get(parsed_args.operation)
        if handler:
            handler()
        else:
            print(f"{UI.STATUS.FAIL} Unsupported operation: {parsed_args.operation}")

    def do_audit(self,  arg:str) -> None:
        """
        Unified cryptographic audit ledger historical trace validation engine interface.
        Usage:
            audit -ls [-l <limit>]
            audit -check [-v]
        """
        tokens = shlex.split(arg.strip())
        if not tokens:
            print(f"{UI.STATUS.FAIL} Operational error: Sub-command operation or arguments missing.")
            return
        
        try:
            parsed_args = self._audit_parser.parse_args(tokens)
        except (ArgumentError, TypeError) as parse_err:
            print(f"{UI.STATUS.FAIL} Syntax Error: {str(parse_err)}")
            return

        dispatch = {
            "-ls": lambda: audit_services.handle_audit_list(self.audit_manager, parsed_args),
            "-check": lambda: audit_services.handle_audit_integrity(self.audit_manager, self.engine.get_ask(), parsed_args),
        }

        handler = dispatch.get(parsed_args.operation)
        if handler:
            handler()
        else:
            print(f"{UI.STATUS.FAIL} Unsupported operation: {parsed_args.operation}")

    def do_exit(self, arg: str) -> bool:
        with Spinner("Purging active workspace boundaries from volatile console process stack..."):
            self.engine.seal()
            time.sleep(0.3)
        print(f"{UI.STATUS.SUCCESS} Active shell process context safely disposed. Goodbye.")
        return True

    def do_EOF(self, arg: str) -> bool:
        print()
        return self.do_exit(arg)