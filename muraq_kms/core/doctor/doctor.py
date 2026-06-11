import os
import json

from pathlib import Path
import sqlite3
from typing import List, Optional

from muraq_kms.storage.config import StorageConfig

from muraq_kms.core.doctor.data_classes import DiagnosticReport, Issue
from muraq_kms.core.throttling import ThrottlingEngine

class DoctorEngine:

    @staticmethod
    def is_system_initialized(config:StorageConfig) -> bool:
        """
        Determines if the KMS is initialized based on consensus and folder hygiene.
        
        Returns:
            True  -> System has data (operational or corrupted/tampered).
            False -> System is a totally blank slate (safe to run 'init').
        """
        anchors = [
            config.base_dir / "manifest.json",
            config.base_dir / "signature.enc",
            config.db_path,
            config.state_db_path
        ]

        existing_anchors = sum(1 for path in anchors if path.exists())
        if existing_anchors == len(anchors):
            return True
        if existing_anchors > 1:
            True

        if config.base_dir.exists():
            allowed = {"state", "audit", "recovery", "backups"}
            ignored = {".DS_Store", "lost+found", ".snapshots"}
                
            for e in os.scandir(config.base_dir):
                if e.name in ignored: continue
                if e.is_dir() and e.name in allowed: continue
                return True
        
        return False

    @staticmethod
    def diagnose(config:StorageConfig) -> DiagnosticReport:
        if not DoctorEngine.is_system_initialized(config):
            return DiagnosticReport(issues=[])
            
        report = DiagnosticReport()

        manifest_issues:List[Issue] = DoctorEngine._diagnose_manifest(config.base_dir)
        report.issues.extend(manifest_issues)
        
        sig_issue = DoctorEngine._diagnose_signature(config.base_dir)
        if sig_issue:
            report.issues.append(sig_issue)
        
        drs_issue:Optional[Issue] = DoctorEngine._diagnose_drs(config.base_dir)
        if drs_issue:
            report.issues.append(drs_issue)
        
        keysdb_issues:List[Issue] = DoctorEngine._diagnose_keysdb(config.db_path)
        report.issues.extend(keysdb_issues)

        deployment_id:Optional[str] = None
        if not manifest_issues:
            deployment_id = DoctorEngine._get_deployment_id(config.base_dir / "manifest.json")

        statedb_issues:List[Issue] = DoctorEngine._diagnose_statedb(config, config.state_db_path, deployment_id)
        report.issues.extend(statedb_issues)

        auditdb_issues:List[Issue] = DoctorEngine._diagnose_auditdb(config.audit_db_path)
        report.issues.extend(auditdb_issues)

        recoverydb_issues:List[Issue] = DoctorEngine._diagnose_recoverydb(config.recovery_db_path)
        report.issues.extend(recoverydb_issues)

        return report

    @staticmethod
    def _diagnose_signature(mkms_path:Path) -> Optional[Issue]:
        sig_path = mkms_path / "signature.enc"
        if not sig_path.exists():
            return Issue(
                "signature.enc",
                "Platform validation anchor file missing. Integrity cannot be verified.",
                is_critical=True, 
                can_fix=False
            )
        return None
    
    @staticmethod
    def _get_deployment_id(manifest:Path) -> Optional[str]:
        try:
            with open(manifest, "r", encoding="utf-8") as m:
                data = json.load(m)
                return data.get("deployment_id", None)
        except Exception:
            return None


    @staticmethod
    def _diagnose_recoverydb(recovery_db:Path) -> List[Issue]:
        issues:List[Issue] = []
        
        if not recovery_db.exists():
            issues.append(Issue(
                "recovery.db", 
                "Recovery emergency keys mapping database layer missing.", 
                is_critical=False, 
                can_fix=True
            ))
        elif not DoctorEngine._verify_sqlite(recovery_db):
            issues.append(Issue(
                "recovery.db", 
                "Recovery ledger records corrupted.", 
                is_critical=False,
                 can_fix=True
            ))

        return issues

    
    @staticmethod
    def _diagnose_auditdb(audit_db:Path) -> List[Issue]:
        issues:List[Issue] = []
        if not audit_db.exists():
            issues.append(Issue(
                "audit.db", 
                "Security event logging ledger missing.", 
                is_critical=False, 
                can_fix=True
            ))
        elif not DoctorEngine._verify_sqlite(audit_db):
            issues.append(Issue(
                "audit.db", 
                "Audit trail tracking data corrupted.", 
                is_critical=False, 
                can_fix=True
            ))
        return issues

    @staticmethod
    def _diagnose_statedb(config:StorageConfig ,state_db:Path, deployment_id:Optional[str] = "UNKNOWN_DEPLOYMENT") -> List[Issue]:
        issues:List[Issue] = []

        if not state_db.exists():
            issues.append(Issue(
                "state.db", 
                "Missing state engine database tracker.", 
                is_critical=False, 
                can_fix=True
            ))
        else:
            if not DoctorEngine._verify_sqlite(state_db):
                issues.append(Issue(
                    "state.db", 
                    "Database file is structurally corrupted.", 
                    is_critical=False, 
                    can_fix=True
                ))
            else:
                try:
                    throttler = ThrottlingEngine(config, deployment_id)
                    status = throttler.check_status()
                    if status.was_tampered:
                        issues.append(Issue(
                            "state.db", 
                            "Tamper signature mismatch detected. Brute-force validation broke.", 
                            is_critical=True, 
                            can_fix=False
                        ))
                except Exception as e:
                    issues.append(Issue(
                        "state.db", 
                        f"Unexpected state tracker failure: {str(e)}", 
                        is_critical=False, 
                        can_fix=True
                    ))

        return issues

    @staticmethod
    def _diagnose_manifest(mkms_path:Path) -> List[Issue]:
        issues:List[Issue] = []

        manifest_path = mkms_path / "manifest.json"
        if not manifest_path.exists():
            issues.append(Issue(
                "manifest.json", 
                "File missing. Critical deployment parameters are gone.", 
                is_critical=True,
                can_fix=False
            ))
        else:
            try:
                with open(manifest_path, 'r', encoding="utf-8") as f:
                    json.load(f)
            except json.JSONDecodeError:
                issues.append(Issue(
                    "manifest.json", 
                    "File malformed/corrupted. Cannot parse parameters safely.",
                    is_critical=True, 
                    can_fix=False
                ))
        return issues
    
    @staticmethod
    def _diagnose_drs(mkms_path:Path) -> Optional[Issue]:
        drs_path = mkms_path / "drs.enc"
        if not drs_path.exists():
            return Issue(
                "drs.enc", 
                "Base encrypted key shares stream missing.", 
                is_critical=True, 
                can_fix=False
            )
    
    @staticmethod
    def _diagnose_keysdb(keys_db:Path) -> List[Issue]:
        issues:List[Issue] = []

        if not keys_db.exists():
            issues.append(Issue(
                "keys.db", 
                "Core master encryption storage database missing.", 
                is_critical=True, 
                can_fix=False
            ))
        else:
            if not DoctorEngine._verify_sqlite(keys_db):
                issues.append(Issue(
                    "keys.db", 
                    "Database corruption detected via PRAGMA check.", 
                    is_critical=True, 
                    can_fix=False
                ))
        return issues
    
    @staticmethod
    def _verify_sqlite(db_path:Path) -> bool:
        try:
            with sqlite3.connect(db_path) as conn:
                cur = conn.execute("PRAGMA integrity_check;")
                row = cur.fetchone()
                return row is not None and row[0] == "ok"
        except sqlite3.Error:
            return False