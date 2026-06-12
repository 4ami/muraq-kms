from muraq_kms.storage.config import StorageConfig
from muraq_kms.storage.migrate import MigrationRunner
from muraq_kms.core.doctor import DoctorEngine
from muraq_kms.core.throttling import ThrottlingEngine

from muraq_kms.cli.ui.ui import UI
from muraq_kms.cli.ui.widgets import Frame

class RepairService:
    @staticmethod
    def execute_repairs(config: StorageConfig, deployment_id:str) -> None:
        config.ensure_layout()
        
        report = DoctorEngine.diagnose(config)
        
        if report.is_healthy:
            print(f" -> {UI.STATUS.SUCCESS} System components verified completely healthy.")
            return

        if report.has_critical:
            print(f"\n{UI.STATUS.CRIT} {UI.COLORS.RED}{UI.ANSIESCAPE.BOLD}CRITICAL REFUSAL:{UI.ANSIESCAPE.RESET} Severe platform integrity violation or forgery detected.")
            print(f"   Auto-repair disabled for administrative custody safety enforcement.\n")
            
            with Frame("Unfixable Severe Anomalies", color=UI.COLORS.RED) as f:
                for issue in report.issues:
                    if not issue.can_fix:
                        f.line(f"{UI.COLORS.RED}•{UI.ANSIESCAPE.RESET} {UI.ANSIESCAPE.BOLD}{issue.asset}{UI.ANSIESCAPE.RESET}: {issue.message}")
            return

        for issue in report.issues:
            if not issue.can_fix:
                print(f" -> {UI.STATUS.WARN} Skipping {UI.COLORS.YELLOW}{issue.asset}{UI.ANSIESCAPE.RESET}: Requires manual administrative disaster discovery intervention.")
                continue

            print(f" -> {UI.STATUS.INFO} Repairing: {UI.ANSIESCAPE.BOLD}{issue.asset}{UI.ANSIESCAPE.RESET}...")
            
            if issue.asset == "state.db":
                RepairService._rebuild_database(config, config.state_db_path, domain="state_db", deployment_id=deployment_id)
            elif issue.asset == "audit.db":
                RepairService._rebuild_database(config, config.audit_db_path, domain="audit_db", deployment_id=deployment_id)
            elif issue.asset == "recovery.db":
                RepairService._rebuild_database(config, config.recovery_db_path, domain="recovery_db", deployment_id=deployment_id)

        print(f"\n -> {UI.STATUS.SUCCESS} Repair pipelines executed. Re-running final diagnostic validation checks...")
        final_check = DoctorEngine.diagnose(config)
        if not final_check.has_critical and all(i.asset != "state.db" for i in final_check.issues):
            print(f" -> {UI.STATUS.SUCCESS} Status update: {UI.COLORS.GREEN}Core system utility restored successfully.{UI.ANSIESCAPE.RESET}")
    
    @staticmethod
    def _rebuild_database(config:StorageConfig, db_path, domain: str, deployment_id:str) -> None:
        try:
            is_state_db_missing = (domain == "state_db" and not db_path.exists())
                
            if db_path.exists():
                db_path.unlink()
            
            runner = MigrationRunner(db_path, domain=domain)
            try:
                runner.upgrade()
            finally:
                runner.close()
            print(f"    {UI.COLORS.CYAN}❯{UI.ANSIESCAPE.RESET} Recreated and migrated {UI.ANSIESCAPE.BOLD}{domain}{UI.ANSIESCAPE.RESET} framework schemas cleanly.")

            if is_state_db_missing:
                print(f"    {UI.STATUS.WARN} {UI.COLORS.YELLOW}Integrity Alert:{UI.ANSIESCAPE.RESET} State tracking database was deleted or missing. Enforcing defensive penalty.")
                print(f"    {UI.STATUS.FAIL} {UI.COLORS.RED}Anti-Reset Shield Active:{UI.ANSIESCAPE.RESET} Carrying forward a 30 min lockout penalty.")
                throttler = ThrottlingEngine(config, deployment_id)
                throttler.enforce_tamper_lockout()
                
        except Exception as e:
            print(f"    {UI.STATUS.FAIL} Error executing recovery block for {UI.COLORS.RED}{domain}{UI.ANSIESCAPE.RESET}: {str(e)}")