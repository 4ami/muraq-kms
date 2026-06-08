class InitializationError(Exception):
    pass

class AlreadyInitializedError(Exception):
    def __init__(self) -> None:
        super().__init__("Muraq-KMS is already initialized. Use `--force` if you explicitly want to wipe and overwrite.")