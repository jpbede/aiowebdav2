"""Tests for the client module."""

from collections.abc import AsyncGenerator
from typing import Any

from aioresponses import CallbackResult, aioresponses
import pytest

from aiowebdav2 import Client
from aiowebdav2.exceptions import MethodNotSupportedError
from aiowebdav2.models import Property, PropertyRequest

from . import load_responses


async def test_list_files(client: Client, responses: aioresponses) -> None:
    """Test list files."""
    responses.add(
        "https://webdav.example.com",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "1"},
        content_type="application/xml",
        status=200,
        body=load_responses("get_list.xml"),
    )

    files = await client.list_files()
    assert len(files) == 2
    assert files == ["test_dir/", "test.txt"]


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
    assert prop.value == "aValue"


async def test_set_property(client: Client, responses: aioresponses) -> None:
    """Test set property."""

    def callback(_url: str, **kwargs: dict[str, Any]) -> CallbackResult:
        assert (
            kwargs["headers"]["Content-Type"].strip()
            == "application/x-www-form-urlencoded"
        )
        assert kwargs["headers"]["Accept"].strip() == "*/*"
        assert kwargs["headers"]["Depth"].strip() == "1"
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
        "https://webdav.example.com/test_dir/test_dir2/",
        "MKCOL",
        headers={"Accept": "*/*"},
        status=201,
    )

    await client.mkdir("/test_dir/test_dir2")


async def test_free(client: Client, responses: aioresponses) -> None:
    """Test free."""
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
