class ExecutionResultCollector:
    """
    An in-memory pytest plugin to catch, clean, and extract precise test 
    metrics and human-readable failure details as they execute.
    """
    def __init__(self) -> None:
        self.tests_run = 0
        self.failures = 0
        self.errors = 0
        self.details = []

    def pytest_runtest_logreport(self, report) -> None:
        if report.when == 'call' or (report.when in ('setup', 'teardown') and report.failed):
            self.tests_run += 1
            
            if report.failed:
                if report.outcome == 'failed':
                    self.failures += 1
                    status_lbl = "FAILURE"
                else:
                    self.errors += 1
                    status_lbl = "ERROR"

                summary = report.nodeid.split("::")[-1]

                self.details.append(f"{status_lbl}: {summary}")