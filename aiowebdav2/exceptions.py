"""Exceptions for aiowebdav2."""

class WebDavException(Exception):
    """Base class for all webdav exceptions."""
    pass


class NotValid(WebDavException):
    """Base class for all not valid exceptions."""
    pass


class OptionNotValid(NotValid):
    """Exception for not valid options."""

    def __init__(self, name, value, ns=""):
        """Exception for not valid options."""
        self.name = name
        self.value = value
        self.ns = ns

    def __str__(self):
        """Return string representation of exception."""
        return f"Option ({self.ns}{self.name}={self.value}) have invalid name or value"


class CertificateNotValid(NotValid):
    """Exception for not valid certificate."""
    pass


class NotFound(WebDavException):
    """Base class for all not found exceptions."""
    pass


class LocalResourceNotFound(NotFound):
    """Exception for not found local resource."""

    def __init__(self, path):
        """Exception for not found local resource."""
        self.path = path

    def __str__(self):
        """Return string representation of exception."""
        return f"Local file: {self.path} not found"


class RemoteResourceNotFound(NotFound):
    """Exception for not found remote resource."""

    def __init__(self, path):
        """Exception for not found remote resource."""
        self.path = path

    def __str__(self):
        """Return string representation of exception."""
        return f"Remote resource: {self.path} not found"


class RemoteParentNotFound(NotFound):
    """Exception for not found remote parent."""

    def __init__(self, path):
        """Exception for not found remote parent."""
        self.path = path

    def __str__(self):
        """Return string representation of exception."""
        return f"Remote parent for: {self.path} not found"


class MethodNotSupported(WebDavException):
    """Exception for not supported method."""

    def __init__(self, name, server):
        """Exception for not supported method."""
        self.name = name
        self.server = server

    def __str__(self):
        """Return string representation of exception."""
        return f"Method '{self.name}' not supported for {self.server}"


class ConnectionException(WebDavException):
    """Exception for connection error."""

    def __init__(self, exception):
        """Exception for connection error."""
        self.exception = exception

    def __str__(self):
        """Return string representation of exception."""
        return self.exception.__str__()


class NoConnection(WebDavException):
    """Exception for no connection."""

    def __init__(self, hostname):
        """Exception for no connection."""
        self.hostname = hostname

    def __str__(self):
        """Return string representation of exception."""
        return f"No connection with {self.hostname}"


# This exception left only for supporting original library interface.
class NotConnection(WebDavException):
    """Exception for no connection."""

    def __init__(self, hostname):
        """Exception for no connection."""
        self.hostname = hostname

    def __str__(self):
        """Return string representation of exception."""
        return f"No connection with {self.hostname}"


class ResponseErrorCode(WebDavException):
    """Exception for response error code."""

    def __init__(self, url, code, message):
        """Exception for response error code."""
        self.url = url
        self.code = code
        self.message = message

    def __str__(self):
        """Return string representation of exception."""
        return f"Request to {self.url} failed with code {self.code} and message: {self.message}"


class NotEnoughSpace(WebDavException):
    """Exception for not enough space on the server."""

    def __init__(self):
        """Exception for not enough space on the server"""
        self.message = "Not enough space on the server"

    def __str__(self):
        """Return string representation of exception."""
        return self.message


class ResourceLocked(WebDavException):
    """Exception for locked resource."""

    def __init__(self, path):
        """Exception for locked resource."""
        self.path = path

    def __str__(self):
        """Return string representation of exception."""
        return f"Resource {self.path} locked"
