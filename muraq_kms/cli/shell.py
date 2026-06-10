import cmd
from typing import Optional

from muraq_kms.storage.config import StorageConfig

from muraq_kms.core.engine import CoreEngine, EngineState

from muraq_kms.cli.services.init_service import init_kms
from muraq_kms.cli.services.unseal_service import unseal_kms

class MKMSShell(cmd.Cmd):
    intro = """
    Muraq KMS v1 Interactive Cryptographic Engine Shell.\n
    Type 'help' or '?' to list commands, or 'exit' to quit.\n
    """
    prompt = "muraq-kms > "

    def __init__(self, config: Optional[StorageConfig] = None) -> None:
        super().__init__()
        self.config = config or StorageConfig.from_env()
        self.engine = CoreEngine(self.config)
        self._update_prompt()

    
    def _update_prompt(self) -> None:
        state = "[UNSEALED]" if self.engine.state == EngineState.UNSEALED else "[SEALED]"
        self.prompt = f"muraq-kms {state} > "

    def postcmd(self, stop: bool, line: str) -> bool:
        self._update_prompt()
        return stop

    def do_init(self, arg: str) -> None:
        """
        Initializes the local appliance deployment state.
        Usage: init [--force]
        """
        if self.engine.state == EngineState.UNSEALED:
            print("[-] Operation Blocked: Cannot initialize an active, unsealed engine.")
            print("[*] Hint: Run the 'seal' command first if you intend to purge data.")
            return
        init_kms(self.config, arg)

    def do_unseal(self, arg:str) -> None:
        """
        Unlocks volatile memory structures and reconstitutes core secrets.
        Usage: unseal
        """
        unseal_kms(self.engine)
    
    def do_seal(self, arg:str) -> None:
        """
        Purges memory registers and locks the engine down immediately.
        Usage: seal
        """
        if self.engine.state == EngineState.SEALED:
            print("[*] Engine is already sealed.")
            return
        print("[*] Wiping volatile keys and zeroing transient operational cache memory buffers...")
        self.engine.seal()
        print("[+] Engine successfully sealed down.")

    def do_exit(self, arg: str) -> bool:
        print("[*] Purging active workspace boundaries from volatile console process stack...")
        self.engine.seal()
        print("[*] Engine sealed.")
        return True

    def do_EOF(self, arg: str) -> bool:
        print()
        return self.do_exit(arg)

    def emptyline(self) -> None:
        pass