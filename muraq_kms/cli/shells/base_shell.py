import os
import cmd

from muraq_kms.storage.config import StorageConfig
from muraq_kms.core.engine import CoreEngine

class BaseKMSShell(cmd.Cmd):
    intro: str = ""
    
    def __init__(self, config: StorageConfig, engine: CoreEngine) -> None:
        super().__init__()
        self.config = config
        self.engine = engine
        self._update_prompt()

    def postcmd(self, stop: bool, line: str) -> bool:
        self._update_prompt()
        return stop

    def _update_prompt(self) -> None:
        raise NotImplementedError
    
    def do_clear(self, arg: str) -> None:
        """
        Clears the terminal screen completely and restores the shell carriage.
        Usage: clear
        """
        os.system('cls' if os.name == 'nt' else 'clear') 
        if self.intro:
            print(self.intro)

    def emptyline(self) -> None:
        pass