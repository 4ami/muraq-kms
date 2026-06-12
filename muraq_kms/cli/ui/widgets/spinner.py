import sys
import time
import threading
import io
from typing import Optional

from muraq_kms.cli.ui.ui import UI, UIColors
from muraq_kms.cli.ui.widgets.frame import Frame

class Spinner:
    _FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, message: str) -> None:
        self.message = message
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._buffer = io.StringIO()
        self._stdout = sys.stdout
    
    def _animate(self) -> None:
        idx = 0
        while self._running:
            frame = Spinner._FRAMES[idx % len(Spinner._FRAMES)]
            sys.stdout.write(f"\r {UI.COLORS.CYAN}{frame}{UI.ANSIESCAPE.RESET} {self.message}")
            sys.stdout.flush()
            idx += 1
            time.sleep(0.08)

    def __enter__(self):
        self._running = True
        self._thread = threading.Thread(target=self._animate, daemon=True)
        self._thread.start()
        sys.stdout = self._buffer
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        sys.stdout = self._stdout

        self._running = False
        if self._thread:
            self._thread.join()
        
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()

        captured = self._buffer.getvalue().strip()
        is_failure = exc_type is not None or f"{UI.STATUS.FAIL}" in captured

        if is_failure:
            print(f" {UI.COLORS.RED}⠋{UI.ANSIESCAPE.RESET} {self.message}")
            frame_title = f"{UI.STATUS.FAIL}{self.message}"
            with Frame(frame_title, color=UI.COLORS.RED) as f:
                for line in captured.splitlines():
                    f.line(line)
        else:
            print(f"{UI.STATUS.SUCCESS} Complete: {self.message}")
            if captured:
                print(captured)
        
        return True


class SpinnerGroup:
    def __init__(self, title: str, color:UIColors = UI.COLORS.MAGENTA) -> None:
        self.title = title
        self.color = color
    
    def __enter__(self):
        UI.frame_header(self.title, UI.COLORS.MAGENTA)
        return self
    
    def run_step(self, message: str, task_callable, *args, **kwargs):
        sys.stdout.write(f"{self.color}│{UI.ANSIESCAPE.RESET} ")
        sys.stdout.flush()
        
        with Spinner(message):
            result = task_callable(*args, **kwargs)
            time.sleep(0.4)
        return result
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        width = 70
        bottom_border = f"{self.color}╰─" + ("─" * (width - 4)) + f"╯{UI.ANSIESCAPE.RESET}"
        print(bottom_border)