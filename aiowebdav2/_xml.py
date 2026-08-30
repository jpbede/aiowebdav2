"""WebDAV XML serialization and parsing."""

import logging
from typing import cast

from lxml import etree

from ._paths import normalize_path, same_path
from .exceptions import RemoteResourceNotFoundError
from .models import DAV, Property, PropertyRequest, QuotaInfo, ResourceInfo

_LOGGER = logging.getLogger(__name__)
_XML_PARSER = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    load_dtd=False,
    huge_tree=False,
)


def parse_xml(content: bytes) -> etree.ElementBase:
    """Parse XML using the package safety policy."""
    return etree.fromstring(content, parser=_XML_PARSER)


def propfind_body(properties: list[PropertyRequest]) -> bytes:
    """Build a PROPFIND body for explicit properties."""
    root = etree.Element("propfind", xmlns=DAV)
    prop = etree.SubElement(root, "prop")
    for item in properties:
        item.append_to(prop)
    return cast("bytes", etree.tostring(root, xml_declaration=True, encoding="UTF-8"))


def quota_body() -> bytes:
    """Build a PROPFIND body for RFC 4331 quota properties."""
    return propfind_body(
        [
            PropertyRequest(name="quota-available-bytes"),
            PropertyRequest(name="quota-used-bytes"),
        ]
    )


def proppatch_body(properties: list[Property]) -> bytes:
    """Build a PROPPATCH body for property updates."""
    root = etree.Element("propertyupdate", xmlns=DAV)
    set_node = etree.SubElement(root, "set")
    prop_node = etree.SubElement(set_node, "prop")
    for item in properties:
        item.append_to(prop_node)
    return cast("bytes", etree.tostring(root, xml_declaration=True, encoding="UTF-8"))


def lock_body() -> bytes:
    """Build a simple exclusive write lock body."""
    root = etree.Element(f"{{{DAV}}}lockinfo", nsmap={"D": DAV})
    scope = etree.SubElement(root, f"{{{DAV}}}lockscope")
    etree.SubElement(scope, f"{{{DAV}}}exclusive")
    lock_type = etree.SubElement(root, f"{{{DAV}}}locktype")
    etree.SubElement(lock_type, f"{{{DAV}}}write")
    return cast("bytes", etree.tostring(root, xml_declaration=True, encoding="UTF-8"))


def parse_resources(content: bytes, hidden_base_path: str) -> list[ResourceInfo]:
    """Parse a WebDAV multistatus body into resource metadata."""
    try:
        tree = parse_xml(content)
    except etree.XMLSyntaxError as err:
        _LOGGER.warning("Failed to parse multistatus XML: %s", err)
        return []

    return [
        resource
        for response in tree.findall(f".//{{{DAV}}}response")
        if (resource := ResourceInfo.from_response(response, hidden_base_path))
        is not None
    ]


def find_resource(
    content: bytes,
    path: str,
    hidden_base_path: str,
) -> ResourceInfo:
    """Find one resource in a WebDAV multistatus body."""
    resources = parse_resources(content, hidden_base_path)
    normalized_path = normalize_path(path, directory=path.endswith("/"))
    for resource in resources:
        if same_path(resource.path, normalized_path):
            return resource
    raise RemoteResourceNotFoundError(path)


def parse_quota(content: bytes, server: str) -> QuotaInfo:
    """Parse RFC 4331 quota information."""
    try:
        tree = parse_xml(content)
    except etree.XMLSyntaxError as err:
        _LOGGER.warning("Failed to parse quota XML: %s", err)
        return QuotaInfo(available_bytes=None, used_bytes=None)

    return QuotaInfo.from_element(tree, server)


def parse_properties(
    content: bytes,
    requested_properties: list[PropertyRequest],
) -> list[Property]:
    """Parse requested properties from a PROPFIND response."""
    tree = parse_xml(content)
    responses = tree.findall(f".//{{{DAV}}}response") or [tree]
    return [
        value
        for item in requested_properties
        for response in responses
        if (value := Property.from_response(response, item)) is not None
    ]


def parse_property_map(
    content: bytes,
    requested_properties: list[PropertyRequest],
    hidden_base_path: str,
) -> dict[str, list[Property]]:
    """Parse requested properties for every resource in a PROPFIND response."""
    tree = parse_xml(content)
    result: dict[str, list[Property]] = {}
    for response in tree.findall(f".//{{{DAV}}}response"):
        resource = ResourceInfo.from_response(response, hidden_base_path)
        if resource is None:
            continue
        result[resource.path] = [
            value
            for item in requested_properties
            if (value := Property.from_response(response, item)) is not None
        ]
    return result
