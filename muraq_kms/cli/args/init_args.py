from pydantic import BaseModel, Field
import re

class InitArgs(BaseModel):
    force:bool = Field(
        False,
        description="Force re-initialization, wiping existing deployment artifacts."
    )


    def ensure_valid_passphrase(self, value:str) -> str:
        LOWER = r"[a-z]"
        UPPER = r"[A-Z]"
        DIGITS = r"\d"
        SPECIAL = r"[@$!%*?&]"

        if not value:
            raise ValueError("Missing passphrase.")
        if not re.search(LOWER, value):
            raise ValueError("Passphrase must contains lower-case letters.")
        if not re.search(UPPER, value):
            raise ValueError("Passphrase must contains upper-case letters.")
        if not re.search(DIGITS, value):
            raise ValueError("Passphrase must contains numbers.")
        if not re.search(SPECIAL, value):
            raise ValueError("Passphrase must contains special characters.")
        return value