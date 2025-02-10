"""Exceptions for aiowebdav2."""


class WebDavError(Exception):
    """Base class for all webdav exceptions."""


class NotValidError(WebDavError):
    """Base class for all not valid exceptions."""


class OptionNotValidError(NotValidError):
    """Exception for not valid options."""

    def __init__(self, name: str, value: str, ns: str = "") -> None:
        """Exception for not valid options."""
        self.name = name
        self.value = value
        self.ns = ns

    def __str__(self) -> str:
        """Return string representation of exception."""
        return f"Option ({self.ns}{self.name}={self.value}) have invalid name or value"


class CertificateNotValidError(NotValidError):
    """Exception for not valid certificate."""


class NotFoundError(WebDavError):
    """Base class for all not found exceptions."""


class LocalResourceNotFoundError(NotFoundError):
    """Exception for not found local resource."""

    def __init__(self, path: str) -> None:
        """Exception for not found local resource."""
        self.path = path

    def __str__(self) -> str:
        """Return string representation of exception."""
        return f"Local file: {self.path} not found"


class RemoteResourceNotFoundError(NotFoundError):
    """Exception for not found remote resource."""

    def __init__(self, path: str) -> None:
        """Exception for not found remote resource."""
        self.path = path

    def __str__(self) -> str:
        """Return string representation of exception."""
        return f"Remote resource: {self.path} not found"


class RemoteParentNotFoundError(NotFoundError):
    """Exception for not found remote parent."""

    def __init__(self, path: str) -> None:
        """Exception for not found remote parent."""
        self.path = path

    def __str__(self) -> str:
        """Return string representation of exception."""
        return f"Remote parent for: {self.path} not found"


class MethodNotSupportedError(WebDavError):
    """Exception for not supported method."""

    def __init__(self, name: str, server: str) -> None:
        """Exception for not supported method."""
        self.name = name
        self.server = server

    def __str__(self) -> str:
        """Return string representation of exception."""
        return f"Method '{self.name}' not supported for {self.server}"


class ConnectionExceptionError(WebDavError):
    """Exception for connection error."""

    def __init__(self, exception: Exception) -> None:
        """Exception for connection error."""
        self.exception = exception

    def __str__(self) -> str:
        """Return string representation of exception."""
        return self.exception.__str__()


class NoConnectionError(WebDavError):
    """Exception for no connection."""

    def __init__(self, hostname: str) -> None:
        """Exception for no connection."""
        self.hostname = hostname

    def __str__(self) -> str:
        """Return string representation of exception."""
        return f"No connection with {self.hostname}"


# This exception left only for supporting original library interface.
class NotConnectionError(WebDavError):
    """Exception for no connection."""

    def __init__(self, hostname: str) -> None:
        """Exception for no connection."""
        self.hostname = hostname

    def __str__(self) -> str:
        """Return string representation of exception."""
        return f"No connection with {self.hostname}"


class ResponseErrorCodeError(WebDavError):
    """Exception for response error code."""

    def __init__(self, url: str, code: int, message: str) -> None:
        """Exception for response error code."""
        self.url = url
        self.code = code
        self.message = message

    def __str__(self) -> str:
        """Return string representation of exception."""
        return (
            f"Request to {self.url} failed with code {self.code} "
            f"and message: {self.message}"
        )


class NotEnoughSpaceError(WebDavError):
    """Exception for not enough space on the server."""

    def __init__(self) -> None:
        """Exception for not enough space on the server."""
        self.message = "Not enough space on the server"

    def __str__(self) -> str:
        """Return string representation of exception."""
        return self.message


class ResourceLockedError(WebDavError):
    """Exception for locked resource."""

    def __init__(self, path: str) -> None:
        """Exception for locked resource."""
        self.path = path

    def __str__(self) -> str:
        """Return string representation of exception."""
        return f"Resource {self.path} locked"


class UnauthorizedError(WebDavError):
    """Exception for unauthorized user."""

    def __init__(self, path: str) -> None:
        """Exception for unauthorized user."""
        self.path = path

    def __str__(self) -> str:
        """Return string representation of exception."""
        return f"Unauthorized access to {self.path}"
