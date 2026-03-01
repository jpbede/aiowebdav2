"""Tests for the client module."""

from collections.abc import AsyncGenerator, AsyncIterable, Callable
import io
import os
import re
import time
from typing import Any

import aiohttp
from aioresponses import CallbackResult, aioresponses
from anyio import Path as AnyioPath
from multidict import CIMultiDict, CIMultiDictProxy
import pytest
import yarl

from aiowebdav2 import Client
from aiowebdav2.client import ClientOptions, _prune_paths
from aiowebdav2.exceptions import (
    AccessDeniedError,
    ConnectionExceptionError,
    LocalResourceNotFoundError,
    MethodNotSupportedError,
    NoConnectionError,
    NotEnoughSpaceError,
    OptionNotValidError,
    RemoteParentNotFoundError,
    RemoteResourceNotFoundError,
    ResourceLockedError,
    ResponseErrorCodeError,
    UnauthorizedError,
)
from aiowebdav2.models import Property, PropertyRequest

from . import load_responses, upload_stream


@pytest.mark.parametrize(
    ("server_path", "response"),
    [
        (
            "/",
            load_responses("get_list.xml"),
        ),
        (
            "/remote.php/webdav/",
            load_responses("nextcloud/get_list.xml"),
        ),
        (
            "/remote.php/webdav/test test/",
            load_responses("nextcloud/get_list_with_spaces.xml"),
        ),
    ],
)
async def test_list_files(
    get_client: Callable[[str], Client],
    server_path: str,
    response: str,
    responses: aioresponses,
) -> None:
    """Test list files."""
    responses.clear()
    responses.add(
        f"https://webdav.example.com{server_path}",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "1"},
        content_type="application/xml",
        status=200,
        body=response,
    )

    client = get_client(server_path)

    files = await client.list_files()
    assert len(files) == 2
    assert files == ["/test_dir/", "/test_dir/test.txt"]


async def test_list_files_empty(client: Client, responses: aioresponses) -> None:
    """Test list files with empty response."""
    responses.clear()
    responses.add(
        "https://webdav.example.com",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "1"},
        content_type="application/xml",
        status=200,
        body=load_responses("get_list_empty.xml"),
    )

    files = await client.list_files()
    assert not files


async def test_list_files_resource_not_found(
    client: Client, responses: aioresponses
) -> None:
    """Test list files with parent not found."""
    responses.add(
        "https://webdav.example.com/test_dir/",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "1"},
        content_type="application/xml",
        status=404,
    )

    with pytest.raises(RemoteResourceNotFoundError):
        await client.list_files("/test_dir/")


async def test_list_files_recursive(client: Client, responses: aioresponses) -> None:
    """Test list files recursively."""
    responses.add(
        "https://webdav.example.com/test_dir/",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "infinity"},
        content_type="application/xml",
        status=200,
        body=load_responses("get_list_recursive.xml"),
    )

    files = await client.list_files("/test_dir/", recursive=True)
    assert len(files) == 3
    assert files == [
        "/test_dir/test.txt",
        "/test_dir/test_dir2/",
        "/test_dir/test_dir2/test.txt",
    ]


async def test_list_with_infos(client: Client) -> None:
    """Test list with infos."""
    files = await client.list_with_infos()
    assert len(files) == 2
    assert files == [
        {
            "content_type": "httpd/unix-directory",
            "created": "2020-04-10T21:59:43Z",
            "etag": '"1000-5a2f6d9cf8d39"',
            "isdir": "True",
            "modified": "Fri, 10 Apr 2020 21:59:43 GMT",
            "name": "",
            "path": "/test_dir/",
            "size": "",
        },
        {
            "content_type": "text/plain",
            "created": "2020-04-10T21:59:43Z",
            "etag": '"29-5a2f6d9cf8d39"',
            "isdir": "False",
            "modified": "Fri, 10 Apr 2020 21:59:43 GMT",
            "name": "",
            "path": "/test_dir/test.txt",
            "size": "41",
        },
    ]


async def test_with_properties(client: Client, responses: aioresponses) -> None:
    """Test list with properties."""
    responses.clear()
    responses.add(
        "https://webdav.example.com/",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "0"},
        content_type="application/xml",
        status=207,
        body=load_responses("list_with_properties.xml"),
    )

    props = await client.list_with_properties(
        properties=[
            PropertyRequest(namespace="test", name="aProperty"),
            PropertyRequest(namespace="test2", name="anotherProperty"),
        ],
    )
    assert props == {
        "/test_dir/test.txt": [
            Property(
                name="aProperty",
                namespace="test",
                value="aValue",
            ),
            Property(
                name="anotherProperty",
                namespace="test2",
                value="anotherValue",
            ),
        ],
        "/test_dir/test2.txt": [
            Property(
                name="aProperty",
                namespace="test",
                value="aValue2",
            ),
            Property(
                name="anotherProperty",
                namespace="test2",
                value="anotherValue2",
            ),
        ],
    }


async def test_info(client: Client, responses: aioresponses) -> None:
    """Test info."""
    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "0"},
        content_type="application/xml",
        status=200,
        body=load_responses("get_info.xml"),
    )
    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "0"},
        content_type="application/xml",
        status=200,
        body=load_responses("is_dir_file.xml"),
    )

    info = await client.info("/test_dir/test.txt")
    assert info == {
        "content_type": "text/plain",
        "created": "2017-10-18T15:16:04Z",
        "etag": "ab0b4b7973803c03639b848682b5f38c",
        "modified": "Wed, 18 Oct 2017 15:16:04 GMT",
        "name": "test.txt",
        "size": "41",
    }


async def test_clean(client: Client, responses: aioresponses) -> None:
    """Test clean."""
    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "DELETE",
        status=204,
    )

    await client.clean("/test_dir/test.txt")


async def test_get_property(client: Client, responses: aioresponses) -> None:
    """Test get property."""
    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "0"},
        content_type="application/xml",
        status=200,
        body=load_responses("get_property.xml"),
    )

    prop = await client.get_property(
        "/test_dir/test.txt", PropertyRequest(namespace="test", name="aProperty")
    )
    assert prop
    assert prop.value == "aValue"


async def test_set_property(client: Client, responses: aioresponses) -> None:
    """Test set property."""

    def callback(_url: str, **kwargs: dict[str, Any]) -> CallbackResult:
        assert (
            kwargs["headers"]["Content-Type"].strip()
            == "application/x-www-form-urlencoded"
        )
        assert kwargs["headers"]["Accept"].strip() == "*/*"
        assert kwargs["headers"]["Depth"].strip() == "0"
        assert kwargs["data"] == (
            b"<?xml version='1.0' encoding='UTF-8'?>\n"
            b'<propertyupdate xmlns="DAV:"><set><prop>'
            b'<aProperty xmlns="test">aValue</aProperty>'
            b"</prop></set></propertyupdate>"
        )

        return CallbackResult(status=207)

    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "PROPPATCH",
        headers={"Accept": "*/*"},
        callback=callback,
    )

    await client.set_property(
        "/test_dir/test.txt",
        Property(namespace="test", name="aProperty", value="aValue"),
    )


async def test_mkdir(client: Client, responses: aioresponses) -> None:
    """Test mkdir."""
    responses.add(
        "https://webdav.example.com/test_dir/",
        "PROPFIND",
        status=200,
        body=load_responses("is_dir_file.xml"),
    )
    responses.add(
        "https://webdav.example.com/test_dir/test_dir2/",
        "MKCOL",
        headers={"Accept": "*/*"},
        status=201,
    )

    await client.mkdir("/test_dir/test_dir2")


async def test_free(client: Client, responses: aioresponses) -> None:
    """Test free."""
    responses.clear()
    responses.add(
        "https://webdav.example.com",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "0"},
        content_type="application/xml",
        status=200,
        body=load_responses("free_space.xml"),
    )

    free = await client.free()
    assert free == 10737417543


async def test_free_not_supported(client: Client, responses: aioresponses) -> None:
    """Test free not supported."""
    responses.clear()
    responses.add(
        "https://webdav.example.com",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "0"},
        content_type="application/xml",
        status=200,
        body=load_responses("free_space_not_supported.xml"),
    )

    with pytest.raises(MethodNotSupportedError):
        await client.free()


async def test_upload_iter(client: Client, responses: aioresponses) -> None:
    """Test upload iter."""

    async def callback(_url: str, **kwargs: Any) -> CallbackResult:
        result = bytearray()
        async for chunk in kwargs["data"]:
            result += chunk
        assert result == b"Hello, world!"
        return CallbackResult(status=201)

    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "PUT",
        headers={"Accept": "*/*"},
        callback=callback,
    )

    async def stream() -> AsyncGenerator[bytes, None]:
        yield b"Hello, "
        yield b"world!"

    await client.upload_iter(stream(), "/test_dir/test.txt")


async def test_download_iter(client: Client, responses: aioresponses) -> None:
    """Test download iter."""

    async def callback(_url: str, **_kwargs: dict[str, Any]) -> CallbackResult:
        return CallbackResult(status=200, body=b"Hello, world!")

    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "GET",
        headers={"Accept": "*/*"},
        callback=callback,
    )
    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "0"},
        content_type="application/xml",
        status=200,
        body=load_responses("is_dir_file.xml"),
    )

    async for chunk in await client.download_iter("/test_dir/test.txt"):
        assert chunk == b"Hello, world!"


async def test_move(client: Client, responses: aioresponses) -> None:
    """Test move."""
    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "MOVE",
        headers={
            "Accept": "*/*",
            "Destination": "https://webdav.example.com/test_dir/test2.txt",
        },
        status=201,
    )

    await client.move("/test_dir/test.txt", "/test_dir/test2.txt")


async def test_check(client: Client, responses: aioresponses) -> None:
    """Test check."""
    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "0"},
        content_type="application/xml",
        status=200,
        body=load_responses("is_dir_file.xml"),
    )

    assert await client.check("/test_dir/test.txt")


async def test_copy(client: Client, responses: aioresponses) -> None:
    """Test copy."""
    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "COPY",
        headers={
            "Accept": "*/*",
            "Destination": "https://webdav.example.com/test_dir/test2.txt",
        },
        status=201,
    )
    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "0"},
        content_type="application/xml",
        status=200,
        body=load_responses("is_dir_file.xml"),
    )

    await client.copy("/test_dir/test.txt", "/test_dir/test2.txt")


async def test_is_dir_not_supported(client: Client, responses: aioresponses) -> None:
    """Test is_dir not supported."""
    responses.add(
        "https://webdav.example.com/test_dir/",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "0"},
        content_type="application/xml",
        status=200,
        body=load_responses("is_dir_directory_not_supported.xml"),
    )

    with pytest.raises(MethodNotSupportedError):
        await client.is_dir("/test_dir/")


async def test_get_properties(client: Client, responses: aioresponses) -> None:
    """Test get properties."""
    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "0"},
        content_type="application/xml",
        status=200,
        body=load_responses("get_property.xml"),
    )

    props = await client.get_properties(
        "/test_dir/test.txt",
        [
            PropertyRequest(namespace="test", name="aProperty"),
            PropertyRequest(namespace="test2", name="anotherProperty"),
        ],
    )
    assert props == [
        Property(
            name="aProperty",
            namespace="test",
            value="aValue",
        ),
        Property(
            name="anotherProperty",
            namespace="test2",
            value="anotherValue",
        ),
    ]


async def test_client_with_internal_session() -> None:
    """Test client with internal session."""
    async with Client(
        url="https://webdav.example.com",
        username="user",
        password="password",
    ) as c:
        assert c._session is not None

    assert c._session.closed


async def test_client_with_external_session() -> None:
    """Test client with external session."""
    external_session = aiohttp.ClientSession()
    async with Client(
        url="https://webdav.example.com",
        username="user",
        password="password",
        options=ClientOptions(session=external_session),
    ) as c:
        assert c._session is not None
        assert c._session is external_session

    assert not c._session.closed

    await external_session.close()
    assert external_session.closed
    assert c._session.closed


async def test_unauthorized(client: Client, responses: aioresponses) -> None:
    """Test unauthorized."""
    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "0"},
        content_type="application/xml",
        status=401,
    )

    with pytest.raises(
        UnauthorizedError,
        match=re.escape("Unauthorized access to https://webdav.example.com"),
    ):
        await client.info("/test_dir/test.txt")


async def test_access_denied(client: Client, responses: aioresponses) -> None:
    """Test access denied."""
    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "0"},
        content_type="application/xml",
        status=403,
    )

    with pytest.raises(
        AccessDeniedError,
        match=re.escape("Access denied to https://webdav.example.com"),
    ):
        await client.info("/test_dir/test.txt")


async def test_upload_iter_content_length(
    client: Client, responses: aioresponses
) -> None:
    """Test upload iter with content length."""

    async def callback(_url: str, **kwargs: Any) -> CallbackResult:
        assert kwargs["headers"]["Content-Length"].strip() == "12"
        return CallbackResult(status=201)

    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "PUT",
        headers={"Accept": "*/*"},
        callback=callback,
    )

    await client.upload_iter(upload_stream(), "/test_dir/test.txt", content_length=12)


async def test_upload_iter_not_enough_space(
    client: Client, responses: aioresponses
) -> None:
    """Test upload iter with not enough space."""
    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "PUT",
        headers={"Accept": "*/*"},
        status=507,
    )

    with pytest.raises(NotEnoughSpaceError):
        await client.upload_iter(
            upload_stream(), "/test_dir/test.txt", content_length=12
        )


async def test_upload_iter_on_dir_fails(
    client: Client, responses: aioresponses
) -> None:
    """Test upload iter on a directory."""
    responses.add(
        "https://webdav.example.com/test_dir/",
        "PUT",
        headers={"Accept": "*/*"},
        status=409,
    )

    with pytest.raises(OptionNotValidError):
        await client.upload_iter(upload_stream(), "/test_dir/")


async def test_upload_iter_parent_missing(responses: aioresponses) -> None:
    """Test upload iter on a directory."""
    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "PUT",
        headers={"Accept": "*/*"},
        status=409,
    )
    responses.add(
        "https://webdav.example.com/test_dir/",
        "PROPFIND",
        headers={"Accept": "*/*"},
        status=404,
    )
    responses.add(
        "https://webdav.example.com/",
        "PROPFIND",
        headers={"Accept": "*/*"},
        status=207,
    )

    async with Client(
        url="https://webdav.example.com",
        username="user",
        password="password",
    ) as client:
        with pytest.raises(
            RemoteParentNotFoundError,
            match=re.escape("Remote parent for: /test_dir/test.txt not found"),
        ):
            await client.upload_iter(upload_stream(), "/test_dir/test.txt")


async def test_prune_paths_helper() -> None:
    """Test prune paths helper."""
    assert _prune_paths(["/root/file", "/root/dir"], "/root/") == [
        "file",
        "dir",
    ]


async def test_get_headers_with_token() -> None:
    """Test get headers with token."""
    async with Client(
        url="https://webdav.example.com",
        username="",
        password="",
        options=ClientOptions(token="mytoken"),
    ) as client:
        headers = client.get_headers("list")
        assert headers["Authorization"] == "Bearer mytoken"


async def test_execute_request_connection_error(responses: aioresponses) -> None:
    """Test execute request connection error."""
    responses.add(
        "https://webdav.example.com/fail",
        "PROPFIND",
        exception=aiohttp.ClientConnectionError(),
    )
    async with Client(
        url="https://webdav.example.com", username="u", password="p"
    ) as client:
        with pytest.raises(NoConnectionError):
            await client.check("/fail")


async def test_execute_request_response_error(responses: aioresponses) -> None:
    """Test execute request response error."""
    responses.add(
        "https://webdav.example.com/fail",
        "PROPFIND",
        exception=aiohttp.ClientResponseError(
            request_info=aiohttp.RequestInfo(
                url=yarl.URL("https://webdav.example.com/fail"),
                method="PROPFIND",
                headers=CIMultiDictProxy(CIMultiDict()),
                real_url=yarl.URL("https://webdav.example.com/fail"),
            ),
            history=(),
        ),
    )
    async with Client(
        url="https://webdav.example.com", username="u", password="p"
    ) as client:
        with pytest.raises(ConnectionExceptionError):
            await client.check("/fail")


async def test_execute_request_locked(responses: aioresponses) -> None:
    """Test execute request locked."""
    responses.add(
        "https://webdav.example.com/locked.txt",
        "PROPFIND",
        status=423,
    )
    async with Client(
        url="https://webdav.example.com", username="u", password="p"
    ) as client:
        with pytest.raises(ResourceLockedError):
            await client.check("/locked.txt")


async def test_execute_request_method_not_supported(responses: aioresponses) -> None:
    """Test execute request method not supported."""
    responses.add(
        "https://webdav.example.com/method.txt",
        "PROPFIND",
        status=405,
    )
    async with Client(
        url="https://webdav.example.com", username="u", password="p"
    ) as client:
        with pytest.raises(MethodNotSupportedError):
            await client.check("/method.txt")


async def test_execute_request_generic_error(responses: aioresponses) -> None:
    """Test execute request generic error."""
    responses.add(
        "https://webdav.example.com/error.txt",
        "PROPFIND",
        status=418,
        body=b"teapot",
    )
    async with Client(
        url="https://webdav.example.com", username="u", password="p"
    ) as client:
        with pytest.raises(ResponseErrorCodeError):
            await client.check("/error.txt")


async def test_list_with_infos_recursive(
    client: Client, responses: aioresponses
) -> None:
    """Test list with infos recursive."""
    responses.clear()
    responses.add(
        "https://webdav.example.com/test_dir/",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "infinity"},
        content_type="application/xml",
        status=200,
        body=load_responses("get_list_recursive.xml"),
    )

    files = await client.list_with_infos("/test_dir/", recursive=True)
    assert len(files) == 3
    assert files[0]["path"].startswith("/test_dir/")


async def test_list_with_properties_none(
    client: Client, responses: aioresponses
) -> None:
    """Test list with properties none."""
    responses.clear()
    responses.add(
        "https://webdav.example.com/",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "1"},
        content_type="application/xml",
        status=207,
        body=load_responses("list_with_properties.xml"),
    )
    props = await client.list_with_properties(properties=None)
    assert "/test_dir/test.txt" in props


async def test_stream_with_progress_sync_and_async(
    client: Client, responses: aioresponses
) -> None:
    """Test stream with progress sync and async."""
    responses.add(
        "https://webdav.example.com/test.txt",
        "GET",
        body=b"content",
        headers={"content-length": "7"},
        status=200,
    )
    response = await client.execute_request("download", "/test.txt")
    output = io.BytesIO()
    sync_calls = []

    def sync_progress(current: int, total: int | None) -> None:
        sync_calls.append((current, total))

    await client._stream_with_progress(response, output.write, sync_progress)
    assert output.getvalue() == b"content"
    assert sync_calls[0] == (0, 7)

    responses.add(
        "https://webdav.example.com/test2.txt",
        "GET",
        body=b"async",
        headers={"content-length": "5"},
        status=200,
    )
    response_async = await client.execute_request("download", "/test2.txt")
    output_async = io.BytesIO()
    async_calls = []

    async def async_progress(current: int, total: int | None) -> None:
        async_calls.append((current, total))

    await client._stream_with_progress(
        response_async, output_async.write, async_progress
    )
    assert output_async.getvalue() == b"async"
    assert async_calls[0] == (0, 5)


async def test_download_from_with_progress(
    client: Client, responses: aioresponses
) -> None:
    """Test download from with progress."""
    responses.add(
        "https://webdav.example.com/test.txt",
        "GET",
        body=b"file content",
        headers={"content-length": "12"},
        status=200,
    )
    progress_calls = []

    def on_progress(current: int, total: int | None) -> None:
        progress_calls.append((current, total))

    buff = io.BytesIO()
    await client.download_from(buff, "/test.txt", progress=on_progress)
    assert buff.getvalue() == b"file content"
    assert progress_calls[0] == (0, 12)


async def test_download_dispatch_file_and_dir(
    client: Client, responses: aioresponses, tmp_path: Any
) -> None:
    """Test download dispatch file and dir."""
    responses.add(
        "https://webdav.example.com/test_dir/",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "1"},
        content_type="application/xml",
        status=200,
        body=load_responses("get_list.xml"),
    )
    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "GET",
        body=b"file content",
        headers={"content-length": "12"},
        status=200,
    )
    responses.add(
        "https://webdav.example.com/test.txt",
        "GET",
        body=b"root file",
        headers={"content-length": "9"},
        status=200,
    )

    local_dir = AnyioPath(tmp_path) / "download_dir"
    await client.download("/test_dir/", local_dir)
    assert (await (local_dir / "test.txt").read_bytes()) == b"file content"

    local_file = AnyioPath(tmp_path) / "test.txt"
    await client.download("/test.txt", local_file)
    assert (await local_file.read_bytes()) == b"root file"


async def test_download_directory_removes_existing(
    client: Client, responses: aioresponses, tmp_path: Any
) -> None:
    """Test download directory removes existing."""
    responses.add(
        "https://webdav.example.com/test_dir/",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "1"},
        content_type="application/xml",
        status=200,
        body=load_responses("get_list.xml"),
    )
    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "GET",
        body=b"file content",
        headers={"content-length": "12"},
        status=200,
    )

    local_dir = AnyioPath(tmp_path) / "download_dir"
    await local_dir.mkdir(parents=True)
    await (local_dir / "old.txt").write_text("old")

    await client.download_directory("/test_dir/", local_dir)
    assert not await (local_dir / "old.txt").exists()
    assert await (local_dir / "test.txt").exists()


async def test_download_file_rejects_directory(client: Client, tmp_path: Any) -> None:
    """Test download file rejects directory."""
    local_dir = AnyioPath(tmp_path) / "target_dir"
    await local_dir.mkdir(parents=True)
    with pytest.raises(OptionNotValidError):
        await client.download_file("/test.txt", local_dir)


async def test_upload_dispatch_file_and_dir(
    client: Client, responses: aioresponses, tmp_path: Any
) -> None:
    """Test upload dispatch file and dir."""
    local_dir = AnyioPath(tmp_path) / "upload_dir"
    await local_dir.mkdir(parents=True)
    local_file = local_dir / "test.txt"
    await local_file.write_text("content")
    responses.add(
        "https://webdav.example.com/test_dir/",
        "MKCOL",
        headers={"Accept": "*/*", "Connection": "Keep-Alive"},
        status=201,
    )

    def upload_callback(_url: str, **_kwargs: dict[str, Any]) -> CallbackResult:
        return CallbackResult(status=201)

    responses.add(
        re.compile(r"https://webdav\.example\.com/test_dir/.+"),
        "PUT",
        headers={"Accept": "*/*"},
        callback=upload_callback,
    )
    await client.upload("/test_dir/", local_dir)

    responses.add(
        "https://webdav.example.com/test.txt",
        "PUT",
        headers={"Accept": "*/*"},
        status=201,
    )
    await client.upload("/test.txt", local_file)


async def test_upload_directory_validations(
    client: Client, responses: aioresponses, tmp_path: Any
) -> None:
    """Test upload directory validations."""
    local_dir = AnyioPath(tmp_path) / "local"
    with pytest.raises(OptionNotValidError):
        await client.upload_directory("/test_dir", local_dir)

    await local_dir.mkdir(parents=True)
    with pytest.raises(OptionNotValidError):
        await client.upload_directory("/test_dir/", local_dir / "file.txt")

    missing_dir = AnyioPath(tmp_path) / "missing"
    with pytest.raises(OptionNotValidError):
        await client.upload_directory("/test_dir/", missing_dir)

    responses.add(
        "https://webdav.example.com/test_dir/",
        "MKCOL",
        headers={"Accept": "*/*", "Connection": "Keep-Alive"},
        status=201,
    )
    await (local_dir / "one.txt").write_text("one")
    responses.add(
        re.compile(r"https://webdav\.example\.com/test_dir/.+"),
        "PUT",
        headers={"Accept": "*/*"},
        status=201,
    )
    await client.upload_directory("/test_dir/", local_dir)


async def test_upload_directory_uses_filename_not_full_path(
    client: Client, responses: aioresponses, tmp_path: Any
) -> None:
    """Test upload directory constructs remote paths from filename, not full local path."""
    local_dir = AnyioPath(tmp_path) / "upload_src"
    await local_dir.mkdir(parents=True)
    await (local_dir / "hello.txt").write_text("data")

    responses.add(
        "https://webdav.example.com/dest/",
        "MKCOL",
        status=201,
    )

    uploaded_urls: list[str] = []

    def upload_callback(_url: str, **_kwargs: dict[str, Any]) -> CallbackResult:
        uploaded_urls.append(str(_url))
        return CallbackResult(status=201)

    responses.add(
        re.compile(r"https://webdav\.example\.com/dest/.+"),
        "PUT",
        callback=upload_callback,
    )

    await client.upload_directory("/dest/", local_dir)

    assert len(uploaded_urls) == 1
    assert uploaded_urls[0] == "https://webdav.example.com/dest/hello.txt"


async def test_upload_file_progress_and_force(
    responses: aioresponses, tmp_path: Any
) -> None:
    """Test upload file progress and force."""
    local_path = AnyioPath(tmp_path) / "file.txt"
    await local_path.write_text("content")

    responses.add(
        "https://webdav.example.com/test_dir/",
        "MKCOL",
        headers={"Accept": "*/*", "Connection": "Keep-Alive"},
        status=201,
    )

    async def upload_callback(_url: str, **kwargs: dict[str, Any]) -> CallbackResult:
        data = kwargs.get("data")
        if isinstance(data, AsyncIterable):
            async for _chunk in data:
                pass
        return CallbackResult(status=201)

    responses.add(
        "https://webdav.example.com/test_dir/file.txt",
        "PUT",
        headers={"Accept": "*/*"},
        callback=upload_callback,
    )
    responses.add(
        "https://webdav.example.com/test_dir/file.txt",
        "PUT",
        headers={"Accept": "*/*"},
        callback=upload_callback,
    )

    progress_calls = []

    def on_progress(current: int, total: int | None) -> None:
        progress_calls.append((current, total))

    async with Client(
        url="https://webdav.example.com", username="u", password="p"
    ) as temp_client:
        await temp_client.upload_file(
            "/test_dir/file.txt", local_path, progress=on_progress, force=True
        )
    assert progress_calls[0][0] == 0


async def test_upload_file_validations(client: Client, tmp_path: Any) -> None:
    """Test upload file validations."""
    local_missing = AnyioPath(tmp_path) / "missing.txt"
    with pytest.raises(LocalResourceNotFoundError):
        await client.upload_file("/test.txt", local_missing)

    local_dir = AnyioPath(tmp_path) / "dir"
    await local_dir.mkdir(parents=True)
    with pytest.raises(OptionNotValidError):
        await client.upload_file("/test.txt", local_dir)

    local_file = AnyioPath(tmp_path) / "file.txt"
    await local_file.write_text("content")
    with pytest.raises(OptionNotValidError):
        await client.upload_file("/test_dir/", local_file)


async def test_copy_directory_adds_depth(
    client: Client, responses: aioresponses
) -> None:
    """Test copy directory adds depth."""
    responses.add(
        "https://webdav.example.com/test_dir/",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "0"},
        content_type="application/xml",
        status=200,
        body=load_responses("is_dir_directory.xml"),
    )

    def callback(_url: str, **kwargs: dict[str, Any]) -> CallbackResult:
        assert kwargs["headers"]["Depth"] == "2"
        return CallbackResult(status=201)

    responses.add(
        "https://webdav.example.com/test_dir/",
        "COPY",
        headers={"Accept": "*/*"},
        callback=callback,
    )
    await client.copy("/test_dir/", "/test_dir_copy/", depth=2)


async def test_lock_and_lock_client_headers(
    client: Client, responses: aioresponses
) -> None:
    """Test lock and lock client headers."""
    responses.add(
        "https://webdav.example.com/test_dir/",
        "LOCK",
        headers={"Lock-Token": "<token123>"},
        status=200,
    )
    responses.add(
        "https://webdav.example.com/test_dir/",
        "UNLOCK",
        status=204,
    )

    lock_client = await client.lock("/test_dir/")
    headers = lock_client.get_headers("check")
    assert headers["Lock-Token"] == "<token123>"
    assert headers["If"] == "(<token123>)"
    await lock_client.__aexit__()


async def test_lock_with_timeout_header(
    client: Client, responses: aioresponses
) -> None:
    """Test lock with timeout header."""

    def callback(_url: str, **kwargs: dict[str, Any]) -> CallbackResult:
        assert kwargs["headers"]["Timeout"] == "Second-10"
        return CallbackResult(status=200, headers={"Lock-Token": "<token>"})

    responses.add(
        "https://webdav.example.com/test_dir/",
        "LOCK",
        headers={"Lock-Token": "<token>"},
        callback=callback,
    )
    responses.add(
        "https://webdav.example.com/test_dir/",
        "UNLOCK",
        status=204,
    )

    lock_client = await client.lock("/test_dir/", timeout=10)
    await lock_client.__aexit__()


async def test_resource_factory(client: Client) -> None:
    """Test resource factory."""
    resource = client.resource("/test_dir/test.txt")
    assert str(resource) == "resource /test_dir/test.txt"


async def test_is_local_more_recent(
    client: Client, responses: aioresponses, tmp_path: Any
) -> None:
    """Test is local more recent."""
    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "1"},
        content_type="application/xml",
        status=200,
        body=load_responses("get_info.xml"),
    )
    local_path = AnyioPath(tmp_path) / "test.txt"
    await local_path.write_text("content")
    now = time.time() + 10
    os.utime(str(local_path), (now, now))
    assert await client.is_local_more_recent(local_path, "/test_dir/test.txt")


async def test_is_local_more_recent_error(
    client: Client, responses: aioresponses, tmp_path: Any
) -> None:
    """Test is local more recent error."""
    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "1"},
        content_type="application/xml",
        status=200,
        body=load_responses("get_info.xml"),
    )
    local_path = AnyioPath(tmp_path) / "test.txt"
    await local_path.write_text("content")
    local_path = AnyioPath(tmp_path) / "missing.txt"
    with pytest.raises(FileNotFoundError):
        await client.is_local_more_recent(local_path, "/test_dir/test.txt")


async def test_push_pull_sync(
    client: Client, responses: aioresponses, tmp_path: Any
) -> None:
    """Test push pull sync."""
    local_dir = AnyioPath(tmp_path) / "local"
    await local_dir.mkdir(parents=True)
    local_file = local_dir / "local.txt"
    await local_file.write_text("content")

    responses.add(
        "https://webdav.example.com/remote/",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "0"},
        content_type="application/xml",
        status=200,
        body=load_responses("is_dir_directory.xml").replace("/test_dir/", "/remote/"),
    )
    responses.add(
        "https://webdav.example.com/remote/",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "0"},
        content_type="application/xml",
        status=200,
        body=load_responses("is_dir_directory.xml").replace("/test_dir/", "/remote/"),
    )
    responses.add(
        "https://webdav.example.com/remote/",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "0"},
        content_type="application/xml",
        status=200,
        body=load_responses("is_dir_directory.xml").replace("/test_dir/", "/remote/"),
    )
    list_body_sync = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<D:multistatus xmlns:D="DAV:">'
        "<D:response><D:href>/remote/</D:href>"
        "<D:propstat><D:prop><D:resourcetype><D:collection/>"
        "</D:resourcetype></D:prop></D:propstat></D:response>"
        "</D:multistatus>"
    )
    responses.add(
        "https://webdav.example.com/remote/",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "1"},
        content_type="application/xml",
        status=200,
        body=list_body_sync,
    )
    responses.add(
        "https://webdav.example.com/remote/local.txt",
        "GET",
        status=200,
        body=b"remote",
        headers={"content-length": "6"},
    )
    responses.add(
        "https://webdav.example.com/remote/local.txt",
        "GET",
        status=200,
        body=b"remote",
        headers={"content-length": "6"},
    )
    responses.add(
        "https://webdav.example.com/remote/local.txt",
        "GET",
        status=200,
        body=b"remote",
        headers={"content-length": "6"},
    )
    responses.add(
        "https://webdav.example.com/remote/local.txt",
        "GET",
        status=200,
        body=b"remote",
        headers={"content-length": "6"},
    )
    responses.add(
        "https://webdav.example.com/remote/",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "1"},
        content_type="application/xml",
        status=200,
        body=list_body_sync,
    )
    responses.add(
        "https://webdav.example.com/remote/local.txt",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "1"},
        content_type="application/xml",
        status=200,
        body=load_responses("get_info.xml").replace(
            "/test_dir/test.txt", "/remote/local.txt"
        ),
    )
    responses.add(
        re.compile(r"https://webdav\.example\.com/remote/.+"),
        "PUT",
        headers={"Accept": "*/*"},
        status=201,
    )
    responses.add(
        "https://webdav.example.com/remote/local.txt",
        "GET",
        status=200,
        body=b"remote",
        headers={"content-length": "6"},
    )

    updated = await client.push("/remote/", local_dir)
    assert updated

    updated = await client.pull("/remote/", local_dir)
    assert updated is False

    responses.add(
        "https://webdav.example.com/remote/",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "0"},
        content_type="application/xml",
        status=200,
        body=load_responses("is_dir_directory.xml").replace("/test_dir/", "/remote/"),
    )
    responses.add(
        "https://webdav.example.com/remote/",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "0"},
        content_type="application/xml",
        status=200,
        body=load_responses("is_dir_directory.xml").replace("/test_dir/", "/remote/"),
    )
    responses.add(
        "https://webdav.example.com/remote/",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "1"},
        content_type="application/xml",
        status=200,
        body=list_body_sync,
    )
    responses.add(
        re.compile(r"https://webdav\.example\.com/remote/.+"),
        "PUT",
        headers={"Accept": "*/*"},
        status=201,
    )
    with pytest.raises(OSError, match=r".+"):
        await client.sync("/remote/", local_dir)


async def test_publish_unpublish(client: Client, responses: aioresponses) -> None:
    """Test publish unpublish."""
    responses.add(
        "https://webdav.example.com/test.txt",
        "PROPPATCH",
        headers={"Accept": "*/*", "Depth": "0"},
        status=207,
    )
    responses.add(
        "https://webdav.example.com/test.txt",
        "PROPPATCH",
        headers={"Accept": "*/*", "Depth": "0"},
        status=207,
    )

    await client.publish("/test.txt")
    await client.unpublish("/test.txt")
