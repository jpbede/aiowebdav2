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
