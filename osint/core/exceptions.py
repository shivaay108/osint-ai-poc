class OSINTError(Exception):
    """Base exception for all OSINT Toolkit errors."""

    pass


class NetworkError(OSINTError):
    """Raised when an HTTP or DNS request fails."""

    pass


class ValidationError(OSINTError):
    """Raised when the input provided to a module is structurally invalid."""

    pass


class RateLimitError(NetworkError):
    """Raised when a remote API or site returns a 429 Too Many Requests."""

    pass


class ResponseTooLargeError(NetworkError):
    """Raised when a download exceeds its size limit."""

    pass
