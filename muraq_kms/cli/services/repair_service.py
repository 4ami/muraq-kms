from muraq_kms.storage.config import StorageConfig
from muraq_kms.storage.migrate import MigrationRunner
from muraq_kms.core.doctor import DoctorEngine
from muraq_kms.core.throttling import ThrottlingEngine

class RepairService:
    @staticmethod
    def execute_repairs(config: StorageConfig, deployment_id:str) -> None:
        print("Initializing repair routine...")
        
        config.ensure_layout()
        
        report = DoctorEngine.diagnose(config)
        
        if report.is_healthy:
            print("System components verified completely healthy.")
            return

        if report.has_critical:
            print("\n🚨 CRITICAL REFUSAL: Severe platform integrity violation or forgery detected.")
            print("Auto-repair disabled for administrative custody safety enforcement.")
            for issue in report.issues:
                if not issue.can_fix:
                    print(f"  -> [CRITICAL] {issue.asset}: {issue.message}")
            return

        for issue in report.issues:
            if not issue.can_fix:
                print(f"Skipping {issue.asset}: Requires manual administrative disaster discovery intervention.")
                continue

            print(f"Repairing: {issue.asset}...")
            
            if issue.asset == "state.db":
                RepairService._rebuild_database(config, config.state_db_path, domain="state_db", deployment_id=deployment_id)
            elif issue.asset == "audit.db":
                RepairService._rebuild_database(config, config.audit_db_path, domain="audit_db", deployment_id=deployment_id)
            elif issue.asset == "recovery.db":
                RepairService._rebuild_database(config, config.recovery_db_path, domain="recovery_db", deployment_id=deployment_id)

        print("\n🎉 Repair routines completed successfully! Re-running diagnostic checks...")
        final_check = DoctorEngine.diagnose(config)
        if not final_check.has_critical and all(i.asset != "state.db" for i in final_check.issues):
            print("Status update: Core system utility restored.")
    
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
            print(f"  -> Recreated and migrated {domain} framework schemas cleanly.")

            if is_state_db_missing:
                print("⚠️ Integrity Alert: State tracking database was deleted or missing. Enforcing defensive penalty.")
                print("🔒 Anti-Reset Shield Active: Carrying forward a 30 min lockout penalty.")
                throttler = ThrottlingEngine(config, deployment_id)
                throttler.enforce_tamper_lockout()
                
        except Exception as e:
            print(f"  -> Error executing recovery block for {domain}: {str(e)}")