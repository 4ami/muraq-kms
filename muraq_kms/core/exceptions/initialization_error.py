from pathlib import Path

class InitializationError(Exception):
    pass

class AlreadyInitializedError(Exception):
    def __init__(self) -> None:
        super().__init__("Muraq-KMS is already initialized. Use `--force` if you explicitly want to wipe and overwrite.")

class UnsafeDirectoryError(Exception):
    def __init__(self, path:Path) -> None:
        super().__init__(
            f"Operation aborted. The directory '{path}' (resolved: {path.resolve()}) "
            f"is deemed unsafe for destructive operations."
        )