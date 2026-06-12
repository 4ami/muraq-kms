from muraq_kms.core.exceptions.engine_error import EngineError

class PolicyDenialError(EngineError):
    """Raised whenever an operation breaks an explicit security policy gate."""
    pass

class LeaseExpiredError(EngineError):
    """Raised when an application attempts to utilize a leased secret outside its valid window."""
    pass