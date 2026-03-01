"""Tests for the exceptions module."""

import pytest

from aiowebdav2.exceptions import (
    AccessDeniedError,
    ConflictError,
    ConnectionExceptionError,
    LocalResourceNotFoundError,
    MethodNotSupportedError,
    NoConnectionError,
    NotEnoughSpaceError,
    OptionNotValidError,
    RemoteParentNotFoundError,
    RemoteResourceNotFoundError,
    ResourceLockedError,
    ResponseErrorCodeError,
    UnauthorizedError,
)


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (
            OptionNotValidError(name="path", value="bad", ns="webdav_"),
            "Option (webdav_path=bad) have invalid name or value",
        ),
        (
            LocalResourceNotFoundError("/missing"),
            "Local file: /missing not found",
        ),
        (
            RemoteResourceNotFoundError("/missing"),
            "Remote resource: /missing not found",
        ),
        (
            RemoteParentNotFoundError("/parent"),
            "Remote parent for: /parent not found",
        ),
        (
            MethodNotSupportedError(name="check", server="https://example.com"),
            "Method 'check' not supported for https://example.com",
        ),
        (
            NoConnectionError("https://example.com"),
            "No connection with https://example.com",
        ),
        (
            ResponseErrorCodeError(
                url="https://example.com/file", code=500, message="boom"
            ),
            "Request to https://example.com/file failed with code 500 and message: boom",
        ),
        (
            NotEnoughSpaceError(),
            "Not enough space on the server",
        ),
        (
            ResourceLockedError("/locked"),
            "Resource /locked locked",
        ),
        (
            UnauthorizedError("https://example.com"),
            "Unauthorized access to https://example.com",
        ),
        (
            AccessDeniedError("https://example.com"),
            "Access denied to https://example.com",
        ),
        (
            ConflictError("/file", "conflict"),
            "Conflict error for /file with message conflict",
        ),
    ],
)
def test_exception_str(exc: Exception, expected: str) -> None:
    """Test exception string representation."""
    assert str(exc) == expected


def test_connection_exception_str() -> None:
    """Test connection exception string representation."""
    exc = ConnectionExceptionError(RuntimeError("boom"))
    assert str(exc) == "boom"
