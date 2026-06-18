from argparse import Namespace
from datetime import datetime, timezone

from muraq_kms.cli.ui.ui import UI
from muraq_kms.cli.ui.widgets import Frame

from muraq_kms.audit.manager import AuditManager

def handle_audit_list(audit_manager:AuditManager, args:Namespace):
    if not audit_manager.repo:
        print(f"{UI.STATUS.FAIL} Operational Error: Audit log repository data store not initialized.")
        return
    
    records = audit_manager.repo.all_sync(asc=False)
    display_rows = records[:args.limit] if records else []

    if not display_rows:
        print(f"{UI.STATUS.INFO} Audit ledger contains zero historical execution trace event vectors.")
        return

    with Frame(title=f" MURAQ-KMS IMMUTABLE AUDIT TRAIL (Last {len(display_rows)} Events) ", color=UI.COLORS.CYAN) as frame:
        for row in display_rows:
            dt_str = datetime.fromtimestamp(float(row[0]), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            
            status_color = UI.COLORS.GREEN if row[4] == "SUCCESS" else UI.COLORS.RED
            status_indicator = "✔" if row[4] == "SUCCESS" else "✗"
            
            header_line = f"[{dt_str}] ID: {row[7]} — {UI.ANSIESCAPE.BOLD}{row[1]}{UI.ANSIESCAPE.RESET}"
            meta_line = f"   Actor : {UI.COLORS.YELLOW}{row[2]}{UI.ANSIESCAPE.RESET} | Status: {status_color}{status_indicator} {row[4]}{UI.ANSIESCAPE.RESET}"
            payload_line = f"   Payload: {UI.ANSIESCAPE.DIM}{row[3]}{UI.ANSIESCAPE.RESET}"
            hash_line = f"   Signature: {UI.ANSIESCAPE.DIM}{str(row[6])[:16]}...{UI.ANSIESCAPE.RESET}"
            
            frame.line(header_line)
            frame.line(meta_line)
            frame.line(payload_line)
            frame.line(hash_line)
            frame.line("—" * 60)
    
def handle_audit_integrity(audit_manager:AuditManager, ask:bytes, args:Namespace):
    print(f"{UI.STATUS.INFO} Executing system audit integrity verification sequential trace...")
    
    try:
        chain_intach, records = audit_manager.verify_chain_integrity_sync(ask, args.verbose)
        if args.verbose and records:
            with Frame(title=f" MURAQ-KMS IMMUTABLE AUDIT TRAIL ({len(records)} Events) ", color=UI.COLORS.CYAN) as frame:
                for record in records:
                    row = record["raw_row"]
                    is_intact = record["is_intact"]
                    
                    dt_str = datetime.fromtimestamp(float(row[0]), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                    
                    status_color = UI.COLORS.GREEN if row[4] == "SUCCESS" else UI.COLORS.RED
                    status_indicator = "✔" if row[4] == "SUCCESS" else "✗"
                    
                    integrity_badge = f"{UI.COLORS.GREEN}✔ INTACT{UI.ANSIESCAPE.RESET}" if is_intact else f"{UI.COLORS.RED}❌ TAMPERED/BROKEN{UI.ANSIESCAPE.RESET}"

                    header_line = f"[{dt_str}] ID: {row[7]} — {UI.ANSIESCAPE.BOLD}{row[1]}{UI.ANSIESCAPE.RESET} [{integrity_badge}]"
                    meta_line = f"   Actor : {UI.COLORS.YELLOW}{row[2]}{UI.ANSIESCAPE.RESET} | Status: {status_color}{status_indicator} {row[4]}{UI.ANSIESCAPE.RESET}"
                    payload_line = f"   Payload: {UI.ANSIESCAPE.DIM}{row[3]}{UI.ANSIESCAPE.RESET}"
                    hash_line = f"   Signature: {UI.ANSIESCAPE.DIM}{str(row[6])[:16]}...{UI.ANSIESCAPE.RESET}"
                    
                    frame.line(header_line)
                    frame.line(meta_line)
                    frame.line(payload_line)
                    frame.line(hash_line)
                    frame.line("—" * 60)
        
        if chain_intach:
            print(f"\n{UI.STATUS.SUCCESS} Audit ledger immutable history fully validated.")
        else:
            print(f"\n{UI.STATUS.FAIL} Audit validation failed: Cryptographic anomalies discovered in chain history.")
    except Exception as e:
        print(f"\n{UI.STATUS.FAIL} Integrity trace halted prematurely: {str(e)}")