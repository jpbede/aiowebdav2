"""Tests for WebDAV XML helpers."""

from datetime import UTC

from lxml import etree
import pytest

from aiowebdav2._xml import (
    find_resource,
    lock_body,
    parse_properties,
    parse_property_map,
    parse_quota,
    parse_resources,
    parse_xml,
    propfind_body,
    proppatch_body,
    quota_body,
)
from aiowebdav2.exceptions import MethodNotSupportedError, RemoteResourceNotFoundError
from aiowebdav2.models import Property, PropertyRequest, QuotaInfo

from . import load_responses


def test_parse_resources() -> None:
    """Test multistatus parsing."""
    resources = parse_resources(load_responses("get_list.xml").encode(), "/")

    assert [item.path for item in resources] == ["/test_dir/", "/test_dir/test.txt"]
    assert resources[0].is_dir
    assert resources[0].size is None
    assert resources[1].size == 41
    assert resources[1].modified
    assert resources[1].modified.tzinfo is UTC


def test_parse_resources_with_hidden_base_path() -> None:
    """Test server URL path is hidden from public paths."""
    resources = parse_resources(
        load_responses("nextcloud/get_list.xml").encode(), "/remote.php/webdav/"
    )
    assert [item.path for item in resources] == ["/test_dir/", "/test_dir/test.txt"]


def test_parse_resources_invalid_xml() -> None:
    """Test invalid multistatus XML returns an empty list."""
    assert parse_resources(b"<not-xml", "/") == []


def test_find_resource() -> None:
    """Test finding one resource by path."""
    resource = find_resource(
        load_responses("is_dir_file.xml").encode(),
        "/test_dir/test.txt",
        "/",
    )
    assert resource.path == "/test_dir/test.txt"
    assert not resource.is_dir


def test_find_resource_missing() -> None:
    """Test missing resource raises."""
    with pytest.raises(RemoteResourceNotFoundError):
        find_resource(
            load_responses("get_list_empty.xml").encode(),
            "/missing",
            "/",
        )


def test_propstat_failures_are_ignored() -> None:
    """Test failed propstat blocks do not produce metadata."""
    content = (
        b'<?xml version="1.0"?>'
        b'<D:multistatus xmlns:D="DAV:">'
        b"<D:response><D:href>/file.txt</D:href><D:propstat>"
        b"<D:prop><D:getcontentlength>123</D:getcontentlength>"
        b"<D:quota-used-bytes>9</D:quota-used-bytes>"
        b"<D:aProperty>nope</D:aProperty></D:prop>"
        b"<D:status>HTTP/1.1 404 Not Found</D:status>"
        b"</D:propstat></D:response></D:multistatus>"
    )

    assert parse_resources(content, "/") == []
    with pytest.raises(RemoteResourceNotFoundError):
        find_resource(content, "/file.txt", "/")
    with pytest.raises(MethodNotSupportedError):
        parse_quota(content, "https://example.com")
    assert parse_properties(content, [PropertyRequest(name="aProperty")]) == []


def test_find_resource_invalid_date() -> None:
    """Test invalid date values are ignored."""
    content = (
        b'<?xml version="1.0"?>'
        b'<d:multistatus xmlns:d="DAV:">'
        b"<d:response><d:href>/file.txt</d:href><d:propstat><d:prop>"
        b"<d:getlastmodified>not-a-date</d:getlastmodified>"
        b"</d:prop></d:propstat></d:response>"
        b"</d:multistatus>"
    )
    assert find_resource(content, "/file.txt", "/").modified is None


def test_parse_quota() -> None:
    """Test quota parsing."""
    assert parse_quota(
        load_responses("free_space.xml").encode(), "https://example.com"
    ) == QuotaInfo(
        available_bytes=10737417543,
        used_bytes=697,
    )
    assert parse_quota(
        load_responses("quota_used_only.xml").encode(), "https://example.com"
    ) == QuotaInfo(
        available_bytes=None,
        used_bytes=697,
    )


def test_parse_quota_not_supported_and_invalid() -> None:
    """Test quota unsupported and invalid XML handling."""
    with pytest.raises(MethodNotSupportedError):
        parse_quota(
            load_responses("free_space_not_supported.xml").encode(),
            "https://example.com",
        )
    assert parse_quota(b"<not-xml", "https://example.com") == QuotaInfo(
        available_bytes=None,
        used_bytes=None,
    )

    with pytest.raises(MethodNotSupportedError):
        parse_quota(
            b'<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">'
            b"<d:quota-used-bytes>abc</d:quota-used-bytes></d:multistatus>",
            "https://example.com",
        )


def test_property_bodies_and_parsing() -> None:
    """Test property XML roundtrip helpers."""
    requests = [
        PropertyRequest(namespace="test", name="aProperty"),
        PropertyRequest(namespace="test2", name="anotherProperty"),
    ]
    body = propfind_body(requests)
    assert etree.fromstring(body).tag.endswith("propfind")

    props = parse_properties(load_responses("get_property.xml").encode(), requests)
    assert props == [
        Property(name="aProperty", namespace="test", value="aValue"),
        Property(name="anotherProperty", namespace="test2", value="anotherValue"),
    ]

    patch_body = proppatch_body(
        [Property(name="aProperty", namespace="test", value="aValue")]
    )
    assert b"aValue" in patch_body


def test_property_map_and_other_bodies() -> None:
    """Test list property parsing plus quota and lock bodies."""
    requests = [
        PropertyRequest(namespace="test", name="aProperty"),
        PropertyRequest(namespace="test2", name="anotherProperty"),
    ]
    result = parse_property_map(
        load_responses("list_with_properties.xml").encode(),
        requests,
        "/",
    )
    assert result["/test_dir/test.txt"][0].value == "aValue"
    assert b"quota-available-bytes" in quota_body()
    assert b"lockinfo" in lock_body()

    without_href = (
        b'<?xml version="1.0"?>'
        b'<d:multistatus xmlns:d="DAV:"><d:response /></d:multistatus>'
    )
    assert not parse_property_map(without_href, requests, "/")


def test_parse_xml_blocks_entities() -> None:
    """Test parser keeps entity expansion disabled."""
    root = parse_xml(
        b"<!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]>"
        b"<root>&test;</root>"
    )
    assert root.text is None
