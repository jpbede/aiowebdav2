"""Tests for the public remote client API."""

from collections.abc import AsyncGenerator
import io
from typing import Any, cast

import aiohttp
from aiointercept import CallbackResult, aiointercept
from multidict import CIMultiDict, CIMultiDictProxy
import pytest
import yarl

from aiowebdav2 import Client, ClientOptions
from aiowebdav2.exceptions import (
    AccessDeniedError,
    ConnectionExceptionError,
    InvalidResponseError,
    MethodNotSupportedError,
    NoConnectionError,
    NotEnoughSpaceError,
    RemoteParentNotFoundError,
    RemoteResourceNotFoundError,
    ResourceLockedError,
    ResponseErrorCodeError,
    UnauthorizedError,
)
from aiowebdav2.models import Property, PropertyRequest, QuotaInfo

from . import load_responses


class _StreamContent:
    """Minimal response content stream for release tests."""

    def __init__(self, chunks: list[bytes]) -> None:
        """Initialize the stream."""
        self._chunks = chunks

    async def read(self, _chunk_size: int) -> bytes:
        """Return the next response chunk."""
        if not self._chunks:
            return b""
        return self._chunks.pop(0)


class _StreamingResponse:
    """Minimal aiohttp-like response for release tests."""

    status = 200
    method = "GET"

    def __init__(self, chunks: list[bytes]) -> None:
        """Initialize the response."""
        self.content = _StreamContent(chunks)
        self.headers: dict[str, str] = {}
        self.released = False

    async def read(self) -> bytes:
        """Return the response body."""
        body = b""
        while chunk := await self.content.read(65536):
            body += chunk
        return body

    def release(self) -> None:
        """Release the response."""
        self.released = True


class _StreamingSession:
    """Minimal aiohttp-like session for release tests."""

    def __init__(self, response: _StreamingResponse) -> None:
        """Initialize the session."""
        self.response = response

    async def request(self, **_kwargs: Any) -> _StreamingResponse:
        """Return the configured response."""
        return self.response

    async def close(self) -> None:
        """Close the session."""


def _client_session(session: object) -> aiohttp.ClientSession:
    """Cast a minimal test double to the aiohttp session interface."""
    return cast("aiohttp.ClientSession", session)


def test_client_can_be_constructed_without_running_loop() -> None:
    """Test client construction does not eagerly create an aiohttp session."""
    client = Client("https://webdav.example.com")

    assert client._http.session is None


@pytest.mark.usefixtures("default_response")
async def test_list_and_stat(client: Client, responses: aiointercept) -> None:
    """Test listing and stat metadata."""
    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "0"},
        content_type="application/xml",
        status=207,
        body=load_responses("is_dir_file.xml"),
    )

    listed = await client.list("/")
    assert [item.path for item in listed] == ["/test_dir/", "/test_dir/test.txt"]
    assert listed[0].is_dir

    stat = await client.stat("/test_dir/test.txt")
    assert stat.path == "/test_dir/test.txt"
    assert stat.size == 41
    assert stat.name == "test.txt"


async def test_is_dir(client: Client, responses: aiointercept) -> None:
    """Test is_dir uses stat metadata."""
    responses.add(
        "https://webdav.example.com/test_dir/",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "0"},
        content_type="application/xml",
        status=207,
        body=load_responses("is_dir_directory.xml"),
    )

    assert await client.is_dir("/test_dir/")


async def test_list_recursive_with_base_path(
    responses: aiointercept,
) -> None:
    """Test recursive listing strips URL base paths."""
    responses.clear()
    responses.add(
        "https://webdav.example.com/remote.php/webdav/test%20test/",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "infinity"},
        content_type="application/xml",
        status=207,
        body=load_responses("nextcloud/get_list_with_spaces.xml"),
    )

    async with Client(
        "https://webdav.example.com/remote.php/webdav/test test/",
        username="user",
        password="password",
    ) as client:
        listed = await client.list("/", recursive=True)

    assert [item.path for item in listed] == ["/test_dir/", "/test_dir/test.txt"]


async def test_exists(client: Client, responses: aiointercept) -> None:
    """Test existence checks."""
    responses.add(
        "https://webdav.example.com/test_dir/",
        "PROPFIND",
        status=207,
        body=load_responses("is_dir_directory.xml"),
    )
    responses.add(
        "https://webdav.example.com/missing.txt",
        "PROPFIND",
        status=404,
    )
    assert await client.exists("/test_dir/")
    assert not await client.exists("/missing.txt")


async def test_mkdir_delete_copy_move(client: Client, responses: aiointercept) -> None:
    """Test write-like WebDAV methods."""
    responses.add("https://webdav.example.com/new/", "MKCOL", status=201)
    responses.add("https://webdav.example.com/old.txt", "DELETE", status=204)
    responses.add("https://webdav.example.com/a.txt", "COPY", status=201)
    responses.add("https://webdav.example.com/b.txt", "MOVE", status=201)

    await client.mkdir("/new/")
    await client.delete("/old.txt")
    await client.copy("/a.txt", "/copy.txt", depth="infinity", overwrite=False)
    await client.move("/b.txt", "/moved.txt", overwrite=True)


async def test_mkdir_parent_missing(
    client: Client,
    responses: aiointercept,
) -> None:
    """Test mkdir reports a missing parent."""
    responses.add("https://webdav.example.com/missing/new/", "MKCOL", status=409)
    responses.add("https://webdav.example.com/missing/", "PROPFIND", status=404)

    with pytest.raises(RemoteParentNotFoundError):
        await client.mkdir("/missing/new/")


async def test_mkdir_parents_exist_ok(
    client: Client,
    responses: aiointercept,
) -> None:
    """Test recursive mkdir tolerates existing parents."""
    responses.add("https://webdav.example.com/a/", "MKCOL", status=405)
    responses.add(
        "https://webdav.example.com/a/",
        "PROPFIND",
        status=207,
        body=load_responses("is_dir_directory.xml").replace("/test_dir/", "/a/"),
    )
    responses.add("https://webdav.example.com/a/b/", "MKCOL", status=201)

    await client.mkdir("/a/b/", parents=True)


async def test_mkdir_exist_ok_missing_after_method_not_supported(
    client: Client,
    responses: aiointercept,
) -> None:
    """Test mkdir re-raises 405 when the directory does not exist."""
    responses.add("https://webdav.example.com/a/", "MKCOL", status=405)
    responses.add("https://webdav.example.com/a/", "PROPFIND", status=404)

    with pytest.raises(MethodNotSupportedError):
        await client.mkdir("/a/", exist_ok=True)


async def test_read_iter_read_and_write(
    client: Client,
    responses: aiointercept,
) -> None:
    """Test reading and writing bytes."""
    responses.add(
        "https://webdav.example.com/file.txt", "GET", body=b"content", status=200
    )
    assert await client.read("/file.txt") == b"content"

    responses.add(
        "https://webdav.example.com/file.txt", "GET", body=b"stream", status=200
    )
    chunks = [chunk async for chunk in client.iter_read("/file.txt")]
    assert chunks == [b"stream"]

    async def stream() -> AsyncGenerator[bytes]:
        yield b"new "
        yield b"content"

    async def callback(_url: str, **kwargs: Any) -> CallbackResult:
        assert kwargs["headers"]["Content-Length"] == "11"
        assert kwargs["data"] == b"new content"
        return CallbackResult(status=201)

    responses.add("https://webdav.example.com/file.txt", "PUT", callback=callback)
    await client.write("/file.txt", stream(), content_length=11)


async def test_iter_read_releases_response_on_early_close() -> None:
    """Test streamed responses are released when callers stop early."""
    response = _StreamingResponse([b"first", b"second"])
    client = Client(
        "https://webdav.example.com",
        options=ClientOptions(session=_client_session(_StreamingSession(response))),
    )
    stream = cast("AsyncGenerator[bytes]", client.iter_read("/file.txt"))

    assert await anext(stream) == b"first"
    await stream.aclose()

    assert response.released


async def test_discarded_response_is_released() -> None:
    """Test mutation helpers release responses they do not read."""
    response = _StreamingResponse([])
    client = Client(
        "https://webdav.example.com",
        options=ClientOptions(session=_client_session(_StreamingSession(response))),
    )

    await client.delete("/file.txt")

    assert response.released


async def test_write_parent_missing(
    client: Client,
    responses: aiointercept,
) -> None:
    """Test write reports a missing parent."""
    responses.add("https://webdav.example.com/missing/file.txt", "PUT", status=409)
    responses.add("https://webdav.example.com/missing/", "PROPFIND", status=404)

    with pytest.raises(RemoteParentNotFoundError):
        await client.write("/missing/file.txt", b"data")


async def test_quota_and_properties(client: Client, responses: aiointercept) -> None:
    """Test quota and property methods."""
    responses.clear()
    responses.add(
        "https://webdav.example.com/",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "0", "Content-Type": "text/xml"},
        status=207,
        body=load_responses("free_space.xml"),
    )
    assert await client.quota() == QuotaInfo(
        available_bytes=10737417543, used_bytes=697
    )

    responses.add(
        "https://webdav.example.com/file.txt",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "0", "Content-Type": "text/xml"},
        status=207,
        body=load_responses("get_property.xml"),
    )
    request = PropertyRequest(namespace="test", name="aProperty")
    assert await client.get_property("/file.txt", request) == Property(
        namespace="test",
        name="aProperty",
        value="aValue",
    )

    responses.add(
        "https://webdav.example.com/",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "1", "Content-Type": "text/xml"},
        status=207,
        body=load_responses("list_with_properties.xml"),
    )
    prop_map = await client.list_properties("/", properties=[request])
    assert prop_map["/test_dir/test.txt"][0].value == "aValue"

    responses.add("https://webdav.example.com/file.txt", "PROPPATCH", status=207)
    await client.set_property(
        "/file.txt",
        Property(namespace="test", name="aProperty", value="new"),
    )


async def test_lock_context(client: Client, responses: aiointercept) -> None:
    """Test lock context unlocks and applies lock token to writes."""
    responses.add(
        "https://webdav.example.com/file.txt",
        "LOCK",
        status=200,
        headers={"Lock-Token": "<token>"},
    )

    async def write_callback(_url: str, **kwargs: Any) -> CallbackResult:
        assert kwargs["headers"]["If"] == "(<token>)"
        return CallbackResult(status=204)

    responses.add("https://webdav.example.com/file.txt", "PUT", callback=write_callback)
    responses.add("https://webdav.example.com/file.txt", "UNLOCK", status=204)

    async with await client.lock("/file.txt") as lock:
        await lock.write(b"content", content_length=7)


async def test_lock_missing_token_raises(
    client: Client,
    responses: aiointercept,
) -> None:
    """Test lock requires a Lock-Token response header."""
    responses.add("https://webdav.example.com/file.txt", "LOCK", status=200)

    with pytest.raises(InvalidResponseError, match="missing Lock-Token"):
        await client.lock("/file.txt")


async def test_lock_read_helpers(client: Client, responses: aiointercept) -> None:
    """Test lock read helpers."""
    responses.add(
        "https://webdav.example.com/file.txt",
        "LOCK",
        status=200,
        headers={"Lock-Token": "<token>"},
    )
    responses.add(
        "https://webdav.example.com/file.txt",
        "GET",
        body=b"content",
        status=200,
    )
    responses.add(
        "https://webdav.example.com/file.txt",
        "GET",
        body=b"stream",
        status=200,
    )
    responses.add("https://webdav.example.com/file.txt", "UNLOCK", status=204)

    async with await client.lock("/file.txt") as lock:
        assert await lock.read() == b"content"
        assert [chunk async for chunk in lock.iter_read()] == [b"stream"]


async def test_auth_and_session_lifetime(responses: aiointercept) -> None:
    """Test auth headers and owned/external sessions."""
    responses.add("https://webdav.example.com/file.txt", "GET", status=200)
    async with Client(
        "https://webdav.example.com",
        options=ClientOptions(token="token"),
    ) as client:
        assert client._http.headers()["Authorization"] == "Bearer token"
        await client.read("/file.txt")
    assert client._http.session is not None
    assert client._http.session.closed

    session = aiohttp.ClientSession()
    async with Client(
        "https://webdav.example.com",
        options=ClientOptions(session=session),
    ) as client:
        assert client._http.session is session
    assert not session.closed
    await session.close()


async def test_basic_auth_header_and_invalid_username() -> None:
    """Test basic auth header generation."""
    async with Client(
        "https://webdav.example.com", username="user", password="pass"
    ) as client:
        assert client._http.headers()["Authorization"].startswith("Basic ")

    async with Client(
        "https://webdav.example.com", username="bad:name", password="pass"
    ) as client:
        with pytest.raises(ValueError, match='A ":" is not allowed'):
            client._http.headers()


async def test_configured_auth_allows_http_origins() -> None:
    """Test configured auth can be sent to HTTP origins."""
    async with Client("http://webdav.example.com") as client:
        assert "Authorization" not in client._http.headers()

    async with Client(
        "http://webdav.example.com",
        options=ClientOptions(token="token"),
    ) as client:
        assert client._http.headers()["Authorization"] == "Bearer token"

    async with Client(
        "http://webdav.example.com",
        username="user",
        password="pass",
    ) as client:
        assert client._http.headers()["Authorization"].startswith("Basic ")


async def test_proxy_headers_are_forwarded() -> None:
    """Test proxy headers option is passed to aiohttp."""

    class Response:
        """Minimal response for transport argument assertions."""

        status = 200
        method = "GET"

        async def read(self) -> bytes:
            """Return an empty body."""
            return b""

    class ProxySession:
        """Session that records request kwargs."""

        def __init__(self) -> None:
            """Initialize the session."""
            self.kwargs: dict[str, Any] | None = None

        async def request(self, **kwargs: Any) -> Response:
            """Record request kwargs."""
            self.kwargs = kwargs
            return Response()

        async def close(self) -> None:
            """Close the session."""

    session = ProxySession()

    async with Client(
        "https://webdav.example.com",
        options=ClientOptions(
            session=_client_session(session),
            proxy="http://proxy.example.com",
            proxy_headers={"Proxy-Authorization": "Basic proxy"},
        ),
    ) as client:
        await client.read("/file.txt")

    assert session.kwargs
    assert session.kwargs["proxy"] == "http://proxy.example.com"
    assert session.kwargs["proxy_headers"] == {"Proxy-Authorization": "Basic proxy"}


@pytest.mark.parametrize(
    ("status", "error"),
    [
        (401, UnauthorizedError),
        (403, AccessDeniedError),
        (404, RemoteResourceNotFoundError),
        (405, MethodNotSupportedError),
        (423, ResourceLockedError),
        (507, NotEnoughSpaceError),
        (500, ResponseErrorCodeError),
    ],
)
async def test_status_errors(
    status: int,
    error: type[Exception],
    responses: aiointercept,
) -> None:
    """Test status code mapping."""
    responses.add(
        "https://webdav.example.com/fail.txt", "GET", status=status, body=b"no"
    )

    async with Client("https://webdav.example.com") as client:
        with pytest.raises(error):
            await client.read("/fail.txt")


async def test_connection_errors(responses: aiointercept) -> None:
    """Test transport exception mapping."""
    responses.add("https://webdav.example.com/fail.txt", "GET", exception=True)

    async with Client("https://webdav.example.com") as client:
        with pytest.raises(NoConnectionError):
            await client.read("/fail.txt")


async def test_response_error_mapping() -> None:
    """Test aiohttp response errors are mapped."""

    class ResponseErrorSession:
        """Session that raises a response error."""

        auth: None = None

        async def request(self, **_kwargs: Any) -> aiohttp.ClientResponse:
            """Raise response error."""
            raise aiohttp.ClientResponseError(
                request_info=aiohttp.RequestInfo(
                    url=yarl.URL("https://webdav.example.com/fail"),
                    method="GET",
                    headers=CIMultiDictProxy(CIMultiDict()),
                    real_url=yarl.URL("https://webdav.example.com/fail"),
                ),
                history=(),
            )

        async def close(self) -> None:
            """Close the session."""

    async with Client(
        "https://webdav.example.com",
        options=ClientOptions(session=_client_session(ResponseErrorSession())),
    ) as client:
        with pytest.raises(ConnectionExceptionError):
            await client.read("/fail.txt")


async def test_request_accepts_file_like(
    client: Client, responses: aiointercept
) -> None:
    """Test write accepts file-like objects."""
    responses.add("https://webdav.example.com/file.txt", "PUT", status=201)
    await client.write("/file.txt", io.BytesIO(b"content"))
