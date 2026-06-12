from enum import Enum
from typing import Optional

class StringEnum(str, Enum):
    def __str__(self) -> str:
        return self.value

    def __format__(self, format_spec: str) -> str:
        return self.value.__format__(format_spec)

class ANSIEscape(StringEnum):
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"

class UIColors(StringEnum):
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    MAGENTA = "\033[35m"

class UIStatus(StringEnum):
    SUCCESS = f"\033[32m✔\033[0m "
    FAIL = f"\033[31m✗\033[0m "
    INFO = f"\033[34mℹ\033[0m "
    WARN = f"\033[33m⚠\033[0m "
    CRIT = f"\033[31m🚨\033[0m "
    HINT = f"\033[36m💡\033[0m "

class UI:
    COLORS = UIColors
    STATUS = UIStatus
    ANSIESCAPE = ANSIEscape
    
    @classmethod
    def frame_header(cls, title:str, color:UIColors = UIColors.BLUE) -> None:
        width = 70
        padding = width - len(title) - 4
        if padding < 0: padding = 0
        print(f"\n{color}╭─ {cls.ANSIESCAPE.BOLD}{title}{cls.ANSIESCAPE.RESET}{color} {"─" * padding}╮{cls.ANSIESCAPE.RESET}")
    
    @classmethod
    def line(cls, content:str, color:UIColors = UIColors.BLUE) -> None:
        print(f"{color}│{cls.ANSIESCAPE.RESET} {content}")

    @classmethod
    def ask_text(cls, question: str, default: Optional[str] = None) -> str:
        hint = f" [{cls.ANSIESCAPE.DIM}{default}{cls.ANSIESCAPE.RESET}]" if default else ""
        prompt_str = f"{cls.STATUS.INFO}{cls.ANSIESCAPE.BOLD}{question}{hint}{cls.ANSIESCAPE.RESET}\n {cls.COLORS.CYAN}❯{cls.ANSIESCAPE.RESET} "
        try:
            val = input(prompt_str).strip()
            return default if (not val and default) else val
        except (KeyboardInterrupt, EOFError):
            print()
            return ""
    
    @classmethod
    def ask_yes_no(cls, question: str, default: bool = False) -> bool:
        opts = f" [{cls.COLORS.GREEN}Y{cls.ANSIESCAPE.RESET}/{cls.ANSIESCAPE.DIM}n{cls.ANSIESCAPE.RESET}]" if default else f" [{cls.ANSIESCAPE.DIM}y{cls.ANSIESCAPE.RESET}/{cls.COLORS.RED}N{cls.ANSIESCAPE.RESET}]"
        prompt_str = f"{cls.STATUS.WARN}{cls.ANSIESCAPE.BOLD}{question}{opts}{cls.ANSIESCAPE.RESET}\n {cls.COLORS.CYAN}❯{cls.ANSIESCAPE.RESET} "
        try:
            val = input(prompt_str).strip().lower()
            if not val:
                return default
            return val in ('y', 'yes', 'true', '1')
        except (KeyboardInterrupt, EOFError):
            print()
            return False
    
