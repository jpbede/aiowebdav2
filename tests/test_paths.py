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


def test_normalize_path() -> None:
    """Test remote path normalization."""
    assert normalize_path("test space/./file") == "/test space/file"
    assert normalize_path("/a/b/../c") == "/a/c"
    assert normalize_path("/a/b/..", directory=True) == "/a/"
    assert normalize_path("") == "/"
    assert normalize_path("../escape") == "/escape"
    assert normalize_path("/") == "/"
    assert normalize_path("file#anchor") == "/file#anchor"
    assert normalize_path("file?query") == "/file?query"
    assert normalize_path("https://example.com/file?query#anchor") == "/file"


def test_parent_and_basename() -> None:
    """Test parent and basename helpers."""
    assert parent_path("/test_dir/test.txt") == "/test_dir/"
    assert parent_path("/test_dir/") == "/"
    assert basename("/") == ""
    assert basename("/test_dir/test child/") == "test child"


def test_join_url_and_base_path() -> None:
    """Test URL joining with encoded paths."""
    assert join_url("https://example.com/dav/", "/", "/test dir/") == (
        "https://example.com/dav/test%20dir/"
    )
    assert join_url("https://example.com/dav/", "/root/", "/file.txt") == (
        "https://example.com/dav/root/file.txt"
    )
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


def test_strip_base_and_same_path() -> None:
    """Test base path stripping and path comparison."""
    assert strip_base("/dav/root/file.txt", "/dav/root/") == "/file.txt"
    assert strip_base("/dav/root/dir/", "/dav/root/", directory=True) == "/dir/"
    assert strip_base("/dav/root/", "/dav/root/", directory=True) == "/"
    assert strip_base("/other/file.txt", "/dav/root/") == "/other/file.txt"
    assert same_path("https://example.com/a%20b/", "/a b/")
    assert same_path("/test_dir", "/test_dir/")
