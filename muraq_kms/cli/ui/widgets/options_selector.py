import sys
from typing import List

from muraq_kms.cli.ui.ui import UI

class _RawReader:
    def __init__(self) -> None:
        try:
            import tty, termios
            self.is_windows = False
        except ImportError:
            self.is_windows = True
            import os
            os.system('')
    
    def get_key(self) -> str:
        if self.is_windows:
            import msvcrt
            ch = msvcrt.getch()
            if ch in (b'\x00', b'\xe0'):
                ch2 = msvcrt.getch()
                if ch2 == b'H': return 'up'
                if ch2 == b'P': return 'down'
            if ch == b'\r': return 'enter'
            try:
                return ch.decode('utf-8').lower()
            except UnicodeDecodeError:
                return ""
        else:
            import tty, termios
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(sys.stdin.fileno())
                ch = sys.stdin.read(1)
                if ch == '\x1b':
                    ch2 = sys.stdin.read(1)
                    if ch2 == '[':
                        ch3 = sys.stdin.read(1)
                        if ch3 == 'A': return 'up'
                        if ch3 == 'B': return 'down'
                    return ch.lower()
                if ch in ('\r', '\n'): return 'enter'
                return ch.lower()
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


class OptionsSelector:
    def __init__(self, prompt:str, choices: List[str], default_idx:int = 0) -> None:
        self.prompt = prompt
        self.choices = choices
        self.current_idx = default_idx
        self.reader = _RawReader()
    
    def _render(self) -> None:
        sys.stdout.write(f"\r\033[K\033[34mℹ\033[0m {UI.ANSIESCAPE.BOLD}{self.prompt}{UI.ANSIESCAPE.RESET} {UI.ANSIESCAPE.DIM}(Use ↑/↓ arrows, Enter to confirm){UI.ANSIESCAPE.RESET}\n")
        for i, choice in enumerate(self.choices):
            sys.stdout.write("\033[K")
            if i == self.current_idx:
                sys.stdout.write(f"  {UI.COLORS.CYAN}❯ {UI.ANSIESCAPE.BOLD}{choice}{UI.ANSIESCAPE.RESET}\n")
            else:
                sys.stdout.write(f"    {UI.ANSIESCAPE.DIM}{choice}{UI.ANSIESCAPE.RESET}\n")
        sys.stdout.write(f"\033[{len(self.choices) + 1}A")
        sys.stdout.flush()
    
    def select(self) -> str:
        sys.stdout.write("\033[?25l")
        sys.stdout.flush()

        try:
            while True:
                self._render()
                key = self.reader.get_key()

                if key == 'up':
                    self.current_idx = (self.current_idx - 1) % len(self.choices)
                elif key == 'down':
                    self.current_idx = (self.current_idx + 1) % len(self.choices)
                elif key == 'enter':
                    for _ in range(len(self.choices) + 1):
                        sys.stdout.write("\033[K\033[1B")
                    sys.stdout.write(f"\033[{len(self.choices) + 1}A\033[K")
                
                    print(f"{UI.STATUS.SUCCESS} {UI.ANSIESCAPE.BOLD}{self.prompt}{UI.ANSIESCAPE.RESET} {UI.ANSIESCAPE.DIM}›{UI.ANSIESCAPE.RESET} {UI.COLORS.GREEN}{self.choices[self.current_idx]}{UI.ANSIESCAPE.RESET}")
                    return self.choices[self.current_idx]
                elif key in ('q', '\x03'):
                    raise KeyboardInterrupt
        finally:
            sys.stdout.write("\033[?25h")
            sys.stdout.flush()
