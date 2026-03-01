"""Tests for the resource module."""

import io
from typing import Any

from aioresponses import aioresponses
from anyio import Path as AnyioPath

from aiowebdav2.client import Client
from aiowebdav2.models import PropertyRequest

from . import load_responses


async def test_resource_is_dir_and_info(
    client: Client, responses: aioresponses
) -> None:
    """Test resource is dir and info."""
    responses.add(
        "https://webdav.example.com/test_dir/",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "0"},
        content_type="application/xml",
        status=200,
        body=load_responses("is_dir_directory.xml"),
    )
    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "1"},
        content_type="application/xml",
        status=200,
        body=load_responses("get_info.xml"),
    )

    dir_resource = client.resource("/test_dir/")
    assert await dir_resource.is_dir()

    file_resource = client.resource("/test_dir/test.txt")
    info = await file_resource.info(params={"name": ""})
    assert info == {"name": "test.txt"}


async def test_resource_rename_move_copy(
    client: Client, responses: aioresponses
) -> None:
    """Test resource rename move copy."""
    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "MOVE",
        headers={
            "Accept": "*/*",
            "Destination": "https://webdav.example.com/test_dir/test2.txt",
            "Overwrite": "F",
        },
        status=201,
    )
    responses.add(
        "https://webdav.example.com/test_dir/test2.txt",
        "MOVE",
        headers={
            "Accept": "*/*",
            "Destination": "https://webdav.example.com/test_dir/test3.txt",
            "Overwrite": "F",
        },
        status=201,
    )
    responses.add(
        "https://webdav.example.com/test_dir/test3.txt",
        "COPY",
        headers={
            "Accept": "*/*",
            "Destination": "https://webdav.example.com/test_dir/test4.txt",
        },
        status=201,
    )
    responses.add(
        "https://webdav.example.com/test_dir/test3.txt",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "0"},
        content_type="application/xml",
        status=200,
        body=load_responses("is_dir_file.xml").replace(
            "/test_dir/test.txt", "/test_dir/test3.txt"
        ),
    )

    resource = client.resource("/test_dir/test.txt")
    await resource.rename("test2.txt")
    assert resource.urn.path() == "/test_dir/test2.txt"

    await resource.move("/test_dir/test3.txt")
    assert resource.urn.path() == "/test_dir/test3.txt"

    new_resource = await resource.copy("/test_dir/test4.txt")
    assert new_resource.urn.path() == "/test_dir/test4.txt"


async def test_resource_clean_check_publish_unpublish(
    client: Client, responses: aioresponses
) -> None:
    """Test resource clean check publish unpublish."""
    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "DELETE",
        status=204,
    )
    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "0"},
        content_type="application/xml",
        status=200,
        body=load_responses("is_dir_file.xml"),
    )
    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "PROPPATCH",
        headers={"Accept": "*/*", "Depth": "0"},
        status=207,
    )
    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "PROPPATCH",
        headers={"Accept": "*/*", "Depth": "0"},
        status=207,
    )

    resource = client.resource("/test_dir/test.txt")
    await resource.clean()
    assert await resource.check()
    await resource.publish()
    await resource.unpublish()


async def test_resource_read_write_paths(
    client: Client, responses: aioresponses, tmp_path: Any
) -> None:
    """Test resource read write paths."""
    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "GET",
        status=200,
        body=b"file content",
        headers={"content-length": "12"},
    )
    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "PUT",
        headers={"Accept": "*/*"},
        status=201,
    )

    local_path = AnyioPath(tmp_path) / "test.txt"
    resource = client.resource("/test_dir/test.txt")
    await resource.read(local_path=local_path)
    assert (await local_path.read_bytes()) == b"file content"

    await local_path.write_bytes(b"upload")
    await resource.write(local_path=local_path)


async def test_resource_read_write_buffers(
    client: Client, responses: aioresponses
) -> None:
    """Test resource read write buffers."""
    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "GET",
        status=200,
        body=b"buffer content",
        headers={"content-length": "14"},
    )
    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "PUT",
        headers={"Accept": "*/*"},
        status=201,
    )

    resource = client.resource("/test_dir/test.txt")
    buff = io.BytesIO()
    await resource.read_from(buff)
    assert buff.getvalue() == b"buffer content"

    await resource.write_to(buff=io.BytesIO(b"upload"))


async def test_resource_get_set_property(
    client: Client, responses: aioresponses
) -> None:
    """Test resource get set property."""
    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "0"},
        content_type="application/xml",
        status=200,
        body=load_responses("get_property.xml"),
    )
    responses.add(
        "https://webdav.example.com/test_dir/test.txt",
        "PROPPATCH",
        headers={"Accept": "*/*"},
        status=207,
    )

    resource = client.resource("/test_dir/test.txt")
    prop = await resource.get_property(
        PropertyRequest(namespace="test", name="aProperty")
    )
    assert prop is not None
    await resource.set_property(name="aProperty", value="aValue", namespace="test")
