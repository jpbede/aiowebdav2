"""Public models for aiowebdav2."""

from dataclasses import dataclass
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import cast

from lxml import etree

from ._paths import basename, strip_base
from .exceptions import MethodNotSupportedError

DAV = "DAV:"


def _qname(namespace: str, name: str) -> str:
    return f"{{{namespace}}}{name}" if namespace else name


def _dav_text(element: etree.ElementBase, name: str) -> str | None:
    value = _find_text(_successful_prop_elements(element), DAV, name)
    return value.strip() if value else None


def _find_text(
    elements: list[etree.ElementBase], namespace: str, name: str
) -> str | None:
    for element in elements:
        value = element.findtext(f".//{_qname(namespace, name)}")
        if value is not None:
            return cast("str", value)
    return None


def _propstat_success(propstat: etree.ElementBase) -> bool:
    status = propstat.findtext(f"{{{DAV}}}status")
    if status is None:
        return True
    parts = status.split(maxsplit=2)
    if len(parts) < 2:
        return False
    try:
        code = int(parts[1])
    except ValueError:
        return False
    return 200 <= code < 300


def _successful_prop_elements(element: etree.ElementBase) -> list[etree.ElementBase]:
    propstats = element.findall(f"{{{DAV}}}propstat")
    if not propstats:
        return [element]

    return [
        prop
        for propstat in propstats
        if _propstat_success(propstat)
        if (prop := propstat.find(f"{{{DAV}}}prop")) is not None
    ]


def _datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        if value.endswith("Z"):
            return datetime.fromisoformat(f"{value[:-1]}+00:00")
        return parsedate_to_datetime(value)
    except ValueError:
        return None


def _int(value: str | None) -> int | None:
    return int(value) if value else None


@dataclass(frozen=True, slots=True, kw_only=True)
class PropertyRequest:
    """Requested WebDAV property."""

    name: str
    namespace: str = "DAV:"

    def append_to(self, parent: etree.ElementBase) -> None:
        """Append this property request to an XML parent."""
        etree.SubElement(parent, _qname(self.namespace, self.name))


@dataclass(frozen=True, slots=True, kw_only=True)
class Property(PropertyRequest):
    """WebDAV property value."""

    value: str

    @classmethod
    def from_response(
        cls,
        response: etree.ElementBase,
        request: PropertyRequest,
    ) -> "Property | None":
        """Build a property from a WebDAV response element."""
        value = _find_text(
            _successful_prop_elements(response), request.namespace, request.name
        )
        if value is None:
            return None
        return cls(name=request.name, namespace=request.namespace, value=value)

    def append_to(self, parent: etree.ElementBase) -> None:
        """Append this property update to an XML parent."""
        node = etree.SubElement(parent, _qname(self.namespace, self.name))
        node.text = self.value


@dataclass(frozen=True, slots=True, kw_only=True)
class QuotaInfo:
    """Quota information for a WebDAV server."""

    available_bytes: int | None
    used_bytes: int | None

    @classmethod
    def from_element(cls, element: etree.ElementBase, server: str) -> "QuotaInfo":
        """Build quota information from a WebDAV XML element."""
        responses = element.findall(f".//{{{DAV}}}response")
        prop_elements = (
            [
                prop
                for response in responses
                for prop in _successful_prop_elements(response)
            ]
            if responses
            else [element]
        )
        available = _find_text(prop_elements, DAV, "quota-available-bytes")
        used = _find_text(prop_elements, DAV, "quota-used-bytes")
        if available is None and used is None:
            raise MethodNotSupportedError(name="quota", server=server)

        try:
            return cls(available_bytes=_int(available), used_bytes=_int(used))
        except ValueError as err:
            raise MethodNotSupportedError(name="quota", server=server) from err


@dataclass(frozen=True, slots=True, kw_only=True)
class ResourceInfo:
    """Metadata for a remote WebDAV resource."""

    path: str
    name: str
    is_dir: bool
    size: int | None = None
    modified: datetime | None = None
    created: datetime | None = None
    etag: str | None = None
    content_type: str | None = None

    @classmethod
    def from_response(
        cls,
        response: etree.ElementBase,
        hidden_base_path: str,
    ) -> "ResourceInfo | None":
        """Build resource metadata from a WebDAV response element."""
        href = response.findtext(f"{{{DAV}}}href")
        if href is None:
            return None
        prop_elements = _successful_prop_elements(response)
        if response.findall(f"{{{DAV}}}propstat") and not prop_elements:
            return None

        is_dir = any(
            prop.find(f".//{{{DAV}}}collection") is not None for prop in prop_elements
        )
        path = strip_base(href, hidden_base_path, directory=is_dir)
        return cls(
            path=path,
            name=_dav_text(response, "displayname") or basename(path),
            is_dir=is_dir,
            size=None if is_dir else _int(_dav_text(response, "getcontentlength")),
            modified=_datetime(_dav_text(response, "getlastmodified")),
            created=_datetime(_dav_text(response, "creationdate")),
            etag=_dav_text(response, "getetag"),
            content_type=_dav_text(response, "getcontenttype"),
        )
