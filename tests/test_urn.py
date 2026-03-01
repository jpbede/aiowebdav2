"""Tests for the urn module."""

from aiowebdav2.urn import Urn


def test_urn_normalizes_and_quotes_path() -> None:
    """Test urn normalizes and quotes path."""
    urn = Urn("test space/./file", directory=False)
    assert urn.path() == "/test space/file"
    assert urn.quote() == "/test%20space/file"


def test_urn_parent_and_filename_for_dir() -> None:
    """Test urn parent and filename for dir."""
    urn = Urn("/test_dir/test child/", directory=True)
    assert urn.filename() == "test child/"
    assert urn.parent() == "/test_dir/"


def test_urn_parent_for_root_child() -> None:
    """Test urn parent for root child."""
    urn = Urn("/test_dir/test.txt")
    assert urn.parent() == "/test_dir/"


def test_urn_is_dir_and_nesting_level() -> None:
    """Test urn is dir and nesting level."""
    urn = Urn("/test_dir/test_dir2/", directory=True)
    assert urn.is_dir()
    assert urn.nesting_level() == 2


def test_urn_normalize_path_and_compare_path() -> None:
    """Test urn normalize path and compare path."""
    normalized = Urn.normalize_path("//test_dir//")
    assert normalized == "/test_dir"
    assert Urn.compare_path("/test_dir", "https://example.com/test_dir")


def test_urn_parent_segment_normalization() -> None:
    """Test urn normalizes parent segment references."""
    assert Urn("/a/b/../c").path() == "/a/c"
    assert Urn("/a/b/c/../../d").path() == "/a/d"
    assert Urn("/parent/..").path() == "/"
    assert Urn("/a/b/..").path() == "/a/"
