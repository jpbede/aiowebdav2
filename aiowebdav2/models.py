"""Models for the aiowebdav2 package."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True, kw_only=True)
class PropertyRequest:
    """Requested property."""

    name: str
    namespace: str


@dataclass(frozen=True, slots=True, kw_only=True)
class Property(PropertyRequest):
    """Property."""

    value: str


@dataclass(frozen=True, slots=True, kw_only=True)
class QuotaInfo:
    """Quota information for a WebDAV server.

    See RFC 4331 for details on the quota properties.
    """

    available_bytes: int | None
    used_bytes: int | None
