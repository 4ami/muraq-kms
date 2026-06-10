from pathlib import Path
from typing import Dict, Any, Optional
import pytest

from muraq_kms.preflight.collector import ExecutionResultCollector

class HealthPreFlight:
    """
    Handles dynamic self-testing and environment validation via programmatic pytest.
    Enforces separation of concerns by isolating diagnostic logic from CLI and storage modules.
    """
    def __init__(self, pr_root: Optional[Path] = None) -> None:
        self.pr_root = pr_root or Path(__file__).resolve().parents[2]
        self.test_dir = self.pr_root / "tests"

    def run_suite(self) -> Dict[str, Any]:
        """
        Programmatically executes pytest over the entire tests/ hierarchy.
        Returns a highly accurate dictionary reflecting true failure metrics and failure reason logs.
        """
        report = {
            "status": "PASSED",
            "tests_run": 0,
            "failures": 0,
            "errors": 0,
            "details": []
        }

        if not self.test_dir.exists():
            report["status"] = 'ERROR'
            report["details"].append(
                f"Diagnostics aborted: Test directory not found at {self.test_dir}"
            )
            return report
        
        collector = ExecutionResultCollector()

        pytest_args = [
            str(self.test_dir),
            "-q",
            "--tb=short"
        ]

        try:
            exit_code = pytest.main(pytest_args, plugins=[collector])
            
            report["tests_run"] = collector.tests_run
            report["failures"] = collector.failures
            report["errors"] = collector.errors

            if exit_code == 0:
                report["status"] = "PASSED"
                report["details"].append(
                    "All localized cryptographic, core lifecycle, and storage domain tests passed successfully."
                )
            elif exit_code in (1, 2):
                report["status"] = "FAILED"
                report["details"].extend(collector.details)
            else:
                report["status"] = "ERROR"
                report["details"].append(f"Pytest exited with abnormal structural code: {exit_code}")
                report["details"].extend(collector.details)
                
        except Exception as e:
            report["status"] = "ERROR"
            report["details"].append(f"Unexpected health check crash: {str(e)}")

        return report

if __name__ == "__main__":
    en = HealthPreFlight()
    print(en.run_suite())