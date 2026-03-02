"""Python3 WebDAV client."""

import warnings

from .client import Client, ClientOptions, LockClient
from .exceptions import (
    AccessDeniedError,
    CertificateNotValidError,
    ConflictError,
    ConnectionExceptionError,
    LocalResourceNotFoundError,
    MethodNotSupportedError,
    NoConnectionError,
    NotEnoughSpaceError,
    NotFoundError,
    NotValidError,
    OptionNotValidError,
    RemoteParentNotFoundError,
    RemoteResourceNotFoundError,
    ResourceLockedError,
    ResponseErrorCodeError,
    UnauthorizedError,
    WebDavError,
)
from .models import Property, PropertyRequest, QuotaInfo


def __getattr__(name: str) -> type:
    if name == "NotConnectionError":
        warnings.warn(
            "NotConnectionError is deprecated, use NoConnectionError instead",
            DeprecationWarning,
            stacklevel=2,
        )
        return NoConnectionError
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)


__all__ = [
    "AccessDeniedError",
    "CertificateNotValidError",
    "Client",
    "ClientOptions",
    "ConflictError",
    "ConnectionExceptionError",
    "LocalResourceNotFoundError",
    "LockClient",
    "MethodNotSupportedError",
    "NoConnectionError",
    "NotEnoughSpaceError",
    "NotFoundError",
    "NotValidError",
    "OptionNotValidError",
    "Property",
    "PropertyRequest",
    "QuotaInfo",
    "RemoteParentNotFoundError",
    "RemoteResourceNotFoundError",
    "ResourceLockedError",
    "ResponseErrorCodeError",
    "UnauthorizedError",
    "WebDavError",
]
