from muraq_kms.cli.ui.ui import UI
from muraq_kms.cli.ui.widgets import Frame

from muraq_kms.crypto.registry import MuraqKMSAlgorithms

def list_algorithms() -> None:
    with Frame(title=" MURAQ-KMS SUPPORTED CRYPTOGRAPHIC ALGORITHMS ", color=UI.COLORS.BLUE) as frame:
            frame.line(f"{UI.COLORS.CYAN}{UI.ANSIESCAPE.BOLD}[ SYMMETRIC PRIMITIVES ]{UI.ANSIESCAPE.RESET}")
            for code in MuraqKMSAlgorithms.SYMMETRIC_CODES:
                spec = MuraqKMSAlgorithms.get_spec(code)
                frame.line(f"💡 {UI.COLORS.YELLOW}{code}{UI.ANSIESCAPE.RESET} — {spec.description}")
            
            frame.line("")
            
            frame.line(f"{UI.COLORS.CYAN}{UI.ANSIESCAPE.BOLD}[ ASYMMETRIC SCHEMES ]{UI.ANSIESCAPE.RESET}")
            for code in MuraqKMSAlgorithms.ASYMMETRIC_CODES:
                spec = MuraqKMSAlgorithms.get_spec(code)
                frame.line(f"💡 {UI.COLORS.YELLOW}{code}{UI.ANSIESCAPE.RESET} — {spec.description}")
            
            frame.line("")
            
            frame.line(
                f"✔ {UI.ANSIESCAPE.DIM}To generate any engine spec layer variant above, execute: "
                f"{UI.COLORS.GREEN}key -create <name> <ALGORITHM_CODE> <purpose encryption/signing/wrapping> [--export] [--borrow] [--ttl]{UI.ANSIESCAPE.RESET}"
            )