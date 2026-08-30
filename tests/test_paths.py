"""Tests for remote path helpers."""

import pytest

from aiowebdav2._paths import (
    base_path,
    basename,
    join_url,
    normalize_path,
    parent_path,
    same_path,
    strip_base,
)
from aiowebdav2.exceptions import OptionNotValidError


@pytest.mark.parametrize(
    ("path", "kwargs", "expected"),
    [
        ("test space/./file", {}, "/test space/file"),
        ("/a/b/../c", {}, "/a/c"),
        ("/a/b/..", {"directory": True}, "/a/"),
        ("", {}, "/"),
        ("../escape", {}, "/escape"),
        ("/", {}, "/"),
        ("file#anchor", {}, "/file#anchor"),
        ("file?query", {}, "/file?query"),
        ("https://example.com/file?query#anchor", {}, "/file"),
    ],
)
def test_normalize_path(path: str, kwargs: dict[str, bool], expected: str) -> None:
    """Test remote path normalization."""
    assert normalize_path(path, **kwargs) == expected


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/test_dir/test.txt", "/test_dir/"),
        ("/test_dir/", "/"),
    ],
)
def test_parent_path(path: str, expected: str) -> None:
    """Test parent path helper."""
    assert parent_path(path) == expected


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/", ""),
        ("/test_dir/test child/", "test child"),
    ],
)
def test_basename(path: str, expected: str) -> None:
    """Test basename helper."""
    assert basename(path) == expected


@pytest.mark.parametrize(
    ("base_url", "root", "path", "expected"),
    [
        (
            "https://example.com/dav/",
            "/",
            "/test dir/",
            "https://example.com/dav/test%20dir/",
        ),
        (
            "https://example.com/dav/",
            "/root/",
            "/file.txt",
            "https://example.com/dav/root/file.txt",
        ),
    ],
)
def test_join_url(base_url: str, root: str, path: str, expected: str) -> None:
    """Test URL joining with encoded paths."""
    assert join_url(base_url, root, path) == expected


def test_base_path() -> None:
    """Test base path helper."""
    assert base_path("https://example.com/dav/", "/root/") == "/dav/root/"


@pytest.mark.parametrize(
    ("root", "path"),
    [
        ("/", "/../escape"),
        ("/", "/%2e%2e/escape"),
        ("/./root/", "/file.txt"),
        ("/root/", "/dir/./file.txt"),
    ],
)
def test_join_url_rejects_relative_path_components(root: str, path: str) -> None:
    """Test URL joining rejects relative path components."""
    with pytest.raises(OptionNotValidError):
        join_url("https://example.com/dav/", root, path)


@pytest.mark.parametrize(
    ("path", "prefix", "kwargs", "expected"),
    [
        ("/dav/root/file.txt", "/dav/root/", {}, "/file.txt"),
        ("/dav/root/dir/", "/dav/root/", {"directory": True}, "/dir/"),
        ("/dav/root/", "/dav/root/", {"directory": True}, "/"),
        ("/other/file.txt", "/dav/root/", {}, "/other/file.txt"),
    ],
)
def test_strip_base(
    path: str,
    prefix: str,
    kwargs: dict[str, bool],
    expected: str,
) -> None:
    """Test base path stripping."""
    assert strip_base(path, prefix, **kwargs) == expected


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("https://example.com/a%20b/", "/a b/"),
        ("/test_dir", "/test_dir/"),
    ],
)
def test_same_path(left: str, right: str) -> None:
    """Test path comparison."""
    assert same_path(left, right)
