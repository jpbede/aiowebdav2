"""Tests for the parser module."""

from lxml import etree
import pytest

from aiowebdav2.exceptions import MethodNotSupportedError, RemoteResourceNotFoundError
from aiowebdav2.models import QuotaInfo
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


def test_extract_response_for_path_skips_none_href() -> None:
    """Test extract_response_for_path skips responses with missing href."""
    root = etree.Element("multistatus", xmlns="DAV:")
    # Response without href - should be skipped
    resp_no_href = etree.SubElement(root, "response")
    etree.SubElement(resp_no_href, "propstat")
    # Response with valid href
    resp_valid = etree.SubElement(root, "response")
    href = etree.SubElement(resp_valid, "href")
    href.text = "/test_dir/"
    content = etree.tostring(etree.ElementTree(root))
    result = WebDavXmlUtils.extract_response_for_path(
        content=content, path="/test_dir/", hostname="https://example.com"
    )
    assert result is not None


def test_parse_quota_response_both_values() -> None:
    """Test parse_quota_response extracts both available and used bytes."""
    content = (
        b'<?xml version="1.0"?>'
        b'<d:multistatus xmlns:d="DAV:">'
        b"<d:response><d:propstat><d:prop>"
        b"<d:quota-available-bytes>500</d:quota-available-bytes>"
        b"<d:quota-used-bytes>200</d:quota-used-bytes>"
        b"</d:prop></d:propstat></d:response>"
        b"</d:multistatus>"
    )
    result = WebDavXmlUtils.parse_quota_response(content, "https://example.com")
    assert result == QuotaInfo(available_bytes=500, used_bytes=200)


def test_parse_quota_response_not_supported() -> None:
    """Test parse_quota_response raises when no quota properties present."""
    content = (
        b'<?xml version="1.0"?>'
        b'<d:multistatus xmlns:d="DAV:">'
        b"<d:response><d:propstat><d:prop/>"
        b"</d:propstat></d:response>"
        b"</d:multistatus>"
    )
    with pytest.raises(MethodNotSupportedError):
        WebDavXmlUtils.parse_quota_response(content, "https://example.com")


def test_parse_quota_response_partial() -> None:
    """Test parse_quota_response with only used_bytes present."""
    content = (
        b'<?xml version="1.0"?>'
        b'<d:multistatus xmlns:d="DAV:">'
        b"<d:response><d:propstat><d:prop>"
        b"<d:quota-used-bytes>42</d:quota-used-bytes>"
        b"</d:prop></d:propstat></d:response>"
        b"</d:multistatus>"
    )
    result = WebDavXmlUtils.parse_quota_response(content, "https://example.com")
    assert result == QuotaInfo(available_bytes=None, used_bytes=42)


def test_parse_quota_response_xml_error() -> None:
    """Test parse_quota_response handles invalid XML gracefully."""
    result = WebDavXmlUtils.parse_quota_response(
        b"<not-xml", hostname="https://example.com"
    )
    assert result == QuotaInfo(available_bytes=None, used_bytes=None)


def test_parse_quota_response_non_numeric() -> None:
    """Test parse_quota_response raises on non-numeric quota values."""
    content = (
        b'<?xml version="1.0"?>'
        b'<d:multistatus xmlns:d="DAV:">'
        b"<d:response><d:propstat><d:prop>"
        b"<d:quota-available-bytes>abc</d:quota-available-bytes>"
        b"</d:prop></d:propstat></d:response>"
        b"</d:multistatus>"
    )
    with pytest.raises(MethodNotSupportedError):
        WebDavXmlUtils.parse_quota_response(content, "https://example.com")
