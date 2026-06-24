import sys
from typing import Callable

from muraq_kms.cli.ui.ui import ANSIEscape, UIColors

class ProgressIndicator:
    @staticmethod
    def _bytes(bytes_done:int, total_bytes:int) -> None:
        if total_bytes <= 0:
            return
        pct = bytes_done * 100 // total_bytes
        mb_done = bytes_done / (1024**2)
        mb_total = total_bytes / (1024**2)

        sys.stdout.write(
            f"\r   {UIColors.CYAN}⠿{ANSIEscape.RESET} "
            f"{pct:3d}%  {mb_done:.1f} / {mb_total:.1f} MiB processed..."
        )
        sys.stdout.flush()
        if bytes_done >= total_bytes:
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()

    @staticmethod
    def _chunk(chunks_done:int, total_chunks:int) -> None:
        if total_chunks <= 0: 
            return
        pct = chunks_done * 100 // total_chunks
        sys.stdout.write(
            f"\r   {UIColors.CYAN}⠿{ANSIEscape.RESET} "
            f"{pct:3d}%  chunk {chunks_done} / {total_chunks}..."
        )
        sys.stdout.flush()
        if chunks_done >= total_chunks:
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()


    @staticmethod
    def build(mode:str = "bytes") -> Callable[[int, int], None]:
        """
        Returns a dynamic streaming progress callback closure that formats and prints 
        a contextual visual meter directly to the terminal line.
        """
        if mode == "bytes":
            return ProgressIndicator._bytes
        else:
            return ProgressIndicator._chunk