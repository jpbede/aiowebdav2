"""Tests for the parser module."""

from lxml import etree
import pytest

from aiowebdav2.exceptions import MethodNotSupportedError, RemoteResourceNotFoundError
from aiowebdav2.parser import WebDavXmlUtils


def test_parse_get_list_info_response_xml_error() -> None:
    """Test parse get list info response xml error."""
    assert not WebDavXmlUtils.parse_get_list_info_response(b"<not-xml")


def test_parse_get_list_property_response_xml_error() -> None:
    """Test parse get list property response xml error."""
    assert not (
        WebDavXmlUtils.parse_get_list_property_response(
            b"<not-xml", properties=[], hostname="https://example.com"
        )
    )


def test_parse_get_list_response_xml_error() -> None:
    """Test parse get list response xml error."""
    assert not WebDavXmlUtils.parse_get_list_response(b"<not-xml")


def test_parse_free_space_response_xml_error() -> None:
    """Test parse free space response xml error."""
    assert (
        WebDavXmlUtils.parse_free_space_response(
            b"<not-xml", hostname="https://example.com"
        )
        is None
    )


def test_extract_response_for_path_xml_error() -> None:
    """Test extract response for path xml error."""
    with pytest.raises(MethodNotSupportedError):
        WebDavXmlUtils.extract_response_for_path(
            content=b"<not-xml",
            path="/test_dir/",
            hostname="https://example.com",
        )


def test_extract_response_for_path_missing_response() -> None:
    """Test extract response for path missing response."""
    root = etree.Element("multistatus", xmlns="DAV:")
    content = etree.tostring(etree.ElementTree(root))
    with pytest.raises(RemoteResourceNotFoundError):
        WebDavXmlUtils.extract_response_for_path(
            content=content, path="/missing", hostname="https://example.com"
        )
