"""Tests for filesystem transfer helpers."""

import asyncio
from pathlib import Path
import re
from typing import Any

from aiointercept import CallbackResult, aiointercept
import pytest

from aiowebdav2 import Client, filesystem
from aiowebdav2.exceptions import LocalResourceNotFoundError, OptionNotValidError
from aiowebdav2.filesystem import download_file, download_tree, upload_file, upload_tree
from aiowebdav2.models import ResourceInfo

from . import load_responses


async def test_download_file(
    client: Client,
    responses: aiointercept,
    tmp_path: Path,
) -> None:
    """Test downloading one file."""
    responses.add(
        "https://webdav.example.com/file.txt",
        "GET",
        body=b"content",
        headers={"content-length": "7"},
        status=200,
    )
    calls: list[tuple[int, int | None]] = []

    def progress(current: int, total: int | None) -> None:
        calls.append((current, total))

    await download_file(client, "/file.txt", tmp_path / "file.txt", progress=progress)

    assert (tmp_path / "file.txt").read_bytes() == b"content"
    assert calls == [(0, 7), (7, 7)]


async def test_download_file_creates_parent_directory(
    client: Client,
    responses: aiointercept,
    tmp_path: Path,
) -> None:
    """Test downloading one file creates missing local parents."""
    responses.add(
        "https://webdav.example.com/file.txt",
        "GET",
        body=b"content",
        status=200,
    )

    await download_file(client, "/file.txt", tmp_path / "nested" / "file.txt")

    assert (tmp_path / "nested" / "file.txt").read_bytes() == b"content"


async def test_upload_file(
    client: Client,
    responses: aiointercept,
    tmp_path: Path,
) -> None:
    """Test uploading one file."""
    local_file = tmp_path / "file.txt"
    local_file.write_text("content")
    calls: list[tuple[int, int | None]] = []

    def progress(current: int, total: int | None) -> None:
        calls.append((current, total))

    async def callback(_url: str, **kwargs: Any) -> CallbackResult:
        assert kwargs["data"] == b"content"
        assert kwargs["headers"]["Content-Length"] == "7"
        return CallbackResult(status=201)

    responses.add("https://webdav.example.com/file.txt", "PUT", callback=callback)
    await upload_file(client, local_file, "/file.txt", progress=progress)

    assert calls == [(0, 7), (7, 7)]


async def test_upload_file_with_parents_and_async_progress(
    client: Client,
    responses: aiointercept,
    tmp_path: Path,
) -> None:
    """Test upload_file can create parents and call async progress."""
    local_file = tmp_path / "file.txt"
    local_file.write_text("content")
    calls: list[tuple[int, int | None]] = []

    async def progress(current: int, total: int | None) -> None:
        calls.append((current, total))

    responses.add("https://webdav.example.com/remote/", "MKCOL", status=201)
    responses.add("https://webdav.example.com/remote/file.txt", "PUT", status=201)

    await upload_file(
        client,
        local_file,
        "/remote/file.txt",
        parents=True,
        progress=progress,
    )

    assert calls == [(0, 7), (7, 7)]


async def test_download_tree(
    client: Client,
    responses: aiointercept,
    tmp_path: Path,
) -> None:
    """Test downloading a directory tree."""
    responses.add(
        "https://webdav.example.com/test_dir/",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "infinity"},
        body=load_responses("get_list_recursive.xml"),
        status=207,
    )
    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "GET",
        body=b"one",
        status=200,
    )
    responses.add(
        "https://webdav.example.com/test_dir/test_dir2/test.txt",
        "GET",
        body=b"two",
        status=200,
    )

    target = tmp_path / "download"
    await download_tree(client, "/test_dir/", target, concurrency=2)

    assert (target / "test.txt").read_bytes() == b"one"
    assert (target / "test_dir2" / "test.txt").read_bytes() == b"two"


async def test_download_tree_creates_missing_file_parents(
    client: Client,
    responses: aiointercept,
    tmp_path: Path,
) -> None:
    """Test download_tree handles file entries without directory entries."""
    responses.add(
        "https://webdav.example.com/remote/",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "infinity"},
        body=(
            '<?xml version="1.0" encoding="utf-8"?>'
            '<D:multistatus xmlns:D="DAV:">'
            "<D:response><D:href>/remote/</D:href>"
            "<D:propstat><D:prop><D:resourcetype><D:collection/>"
            "</D:resourcetype></D:prop></D:propstat></D:response>"
            "<D:response><D:href>/remote/nested/file.txt</D:href>"
            "<D:propstat><D:prop><D:getcontentlength>7</D:getcontentlength>"
            "</D:prop></D:propstat></D:response>"
            "</D:multistatus>"
        ),
        status=207,
    )
    responses.add(
        "https://webdav.example.com/remote/nested/file.txt",
        "GET",
        body=b"content",
        status=200,
    )

    target = tmp_path / "download"
    await download_tree(client, "/remote/", target)

    assert (target / "nested" / "file.txt").read_bytes() == b"content"


async def test_download_tree_rejects_resources_outside_root(
    client: Client,
    responses: aiointercept,
    tmp_path: Path,
) -> None:
    """Test download_tree rejects listed resources outside the remote root."""
    responses.add(
        "https://webdav.example.com/remote/",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "infinity"},
        body=(
            '<?xml version="1.0" encoding="utf-8"?>'
            '<D:multistatus xmlns:D="DAV:">'
            "<D:response><D:href>/outside.txt</D:href>"
            "<D:propstat><D:prop><D:getcontentlength>7</D:getcontentlength>"
            "</D:prop></D:propstat></D:response>"
            "</D:multistatus>"
        ),
        status=207,
    )

    with pytest.raises(OptionNotValidError, match="remote_path"):
        await download_tree(client, "/remote/", tmp_path / "download")


async def test_download_tree_rejects_backslash_resource_paths(
    client: Client,
    responses: aiointercept,
    tmp_path: Path,
) -> None:
    """Test download_tree rejects encoded backslashes before local mapping."""
    responses.add(
        "https://webdav.example.com/remote/",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "infinity"},
        body=(
            '<?xml version="1.0" encoding="utf-8"?>'
            '<D:multistatus xmlns:D="DAV:">'
            "<D:response><D:href>/remote/%5Coutside.txt</D:href>"
            "<D:propstat><D:prop><D:getcontentlength>7</D:getcontentlength>"
            "</D:prop></D:propstat></D:response>"
            "</D:multistatus>"
        ),
        status=207,
    )

    with pytest.raises(OptionNotValidError, match="remote_path"):
        await download_tree(client, "/remote/", tmp_path / "download")


async def test_download_tree_cancels_unfinished_siblings(
    client: Client,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Test download_tree cancels sibling tasks when one download fails."""
    started = asyncio.Event()
    cancelled = False

    async def list_resources(
        _path: str,
        *,
        recursive: bool = False,
    ) -> list[ResourceInfo]:
        assert recursive
        return [
            ResourceInfo(path="/remote/slow.txt", name="slow.txt", is_dir=False),
            ResourceInfo(path="/remote/fail.txt", name="fail.txt", is_dir=False),
        ]

    async def fake_download_file(
        _client: Client,
        remote_path: str,
        _local_path: Path,
        *,
        progress: filesystem.ProgressCallback | None = None,
    ) -> None:
        assert progress is None
        if remote_path == "/remote/slow.txt":
            nonlocal cancelled
            started.set()
            try:
                await asyncio.sleep(60)
            except asyncio.CancelledError:
                cancelled = True
                raise
        await started.wait()
        msg = "download failed"
        raise RuntimeError(msg)

    monkeypatch.setattr(client, "list", list_resources)
    monkeypatch.setattr(filesystem, "download_file", fake_download_file)

    with pytest.raises(RuntimeError, match="download failed"):
        await download_tree(client, "/remote/", tmp_path / "download", concurrency=2)

    assert cancelled


async def test_upload_tree(
    client: Client,
    responses: aiointercept,
    tmp_path: Path,
) -> None:
    """Test uploading a directory tree."""
    source = tmp_path / "upload"
    (source / "nested").mkdir(parents=True)
    (source / "a.txt").write_text("a")
    (source / "nested" / "b.txt").write_text("b")

    responses.add("https://webdav.example.com/remote/", "MKCOL", status=201)
    responses.add("https://webdav.example.com/remote/nested/", "MKCOL", status=201)
    uploaded: list[str] = []

    def upload_callback(url: str, **_kwargs: Any) -> CallbackResult:
        uploaded.append(str(url))
        return CallbackResult(status=201)

    responses.add(
        re.compile(r"https://webdav\.example\.com/remote/.+\.txt"),
        "PUT",
        callback=upload_callback,
    )
    responses.add(
        re.compile(r"https://webdav\.example\.com/remote/.+\.txt"),
        "PUT",
        callback=upload_callback,
    )

    await upload_tree(client, source, "/remote/", concurrency=2)

    assert sorted(uploaded) == [
        "https://webdav.example.com/remote/a.txt",
        "https://webdav.example.com/remote/nested/b.txt",
    ]


async def test_upload_tree_cancels_unfinished_siblings(
    client: Client,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Test upload_tree cancels sibling tasks when one upload fails."""
    source = tmp_path / "upload"
    source.mkdir()
    (source / "slow.txt").write_text("slow")
    (source / "fail.txt").write_text("fail")
    started = asyncio.Event()
    cancelled = False

    async def mkdir(
        _path: str,
        *,
        parents: bool = False,
        exist_ok: bool = False,
    ) -> None:
        assert parents
        assert exist_ok

    async def fake_upload_file(
        _client: Client,
        local_path: Path,
        _remote_path: str,
        *,
        parents: bool = False,
        progress: filesystem.ProgressCallback | None = None,
    ) -> None:
        assert not parents
        assert progress is None
        if local_path.name == "slow.txt":
            nonlocal cancelled
            started.set()
            try:
                await asyncio.sleep(60)
            except asyncio.CancelledError:
                cancelled = True
                raise
        await started.wait()
        msg = "upload failed"
        raise RuntimeError(msg)

    monkeypatch.setattr(client, "mkdir", mkdir)
    monkeypatch.setattr(filesystem, "upload_file", fake_upload_file)

    with pytest.raises(RuntimeError, match="upload failed"):
        await upload_tree(client, source, "/remote/", concurrency=2)

    assert cancelled


async def test_filesystem_validations(client: Client, tmp_path: Path) -> None:
    """Test filesystem validation errors."""
    directory = tmp_path / "dir"
    directory.mkdir()

    with pytest.raises(OptionNotValidError):
        await download_file(client, "/file.txt", directory)
    with pytest.raises(LocalResourceNotFoundError):
        await upload_file(client, tmp_path / "missing.txt", "/missing.txt")
    with pytest.raises(OptionNotValidError):
        await upload_file(client, directory, "/dir")
    with pytest.raises(OptionNotValidError):
        await download_tree(client, "/remote/", tmp_path / "target", concurrency=0)
    with pytest.raises(OptionNotValidError):
        await upload_tree(client, directory, "/remote/", concurrency=0)
    local_file = tmp_path / "target.txt"
    local_file.write_text("content")
    with pytest.raises(OptionNotValidError):
        await download_tree(client, "/remote/", local_file)
    with pytest.raises(LocalResourceNotFoundError):
        await upload_tree(client, tmp_path / "missing", "/remote/")
    (directory / "file.txt").write_text("content")
    with pytest.raises(OptionNotValidError):
        await upload_tree(client, directory / "file.txt", "/remote/")


async def test_download_tree_overwrite_false(
    client: Client,
    tmp_path: Path,
) -> None:
    """Test download_tree rejects existing target by default."""
    target = tmp_path / "target"
    target.mkdir()
    with pytest.raises(FileExistsError):
        await download_tree(client, "/remote/", target)


async def test_download_tree_overwrites_existing_directory(
    client: Client,
    responses: aiointercept,
    tmp_path: Path,
) -> None:
    """Test download_tree removes existing target when requested."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "old.txt").write_text("old")
    responses.add(
        "https://webdav.example.com/remote/",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "infinity"},
        body=(
            '<?xml version="1.0" encoding="utf-8"?>'
            '<D:multistatus xmlns:D="DAV:">'
            "<D:response><D:href>/remote/</D:href>"
            "<D:propstat><D:prop><D:resourcetype><D:collection/>"
            "</D:resourcetype></D:prop></D:propstat></D:response>"
            "</D:multistatus>"
        ),
        status=207,
    )

    await download_tree(client, "/remote/", target, overwrite=True)

    assert not (target / "old.txt").exists()
