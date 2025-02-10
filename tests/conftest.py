"""Fixtures for aiowebdav2 tests."""

from collections.abc import AsyncGenerator, Generator

import aiohttp
from aioresponses import aioresponses
import pytest

from aiowebdav2 import Client
from tests import load_responses


@pytest.fixture(name="responses")
def aioresponses_fixture() -> Generator[aioresponses, None, None]:
    """Return aioresponses fixture."""
    with aioresponses() as mocked_responses:
        yield mocked_responses


@pytest.fixture(autouse=True)
def mock_responses(responses: aioresponses) -> None:
    """Add default responses."""
    responses.add(
        "https://webdav.example.com",
        "PROPFIND",
        headers={"Accept": "*/*", "Depth": "1"},
        content_type="application/xml",
        status=200,
        body=load_responses("get_list.xml"),
    )


@pytest.fixture(name="client")
async def client() -> AsyncGenerator[Client, None]:
    """Return a aiowebdav2 client."""
    webdav_options: dict[str, str | int | bool] = {
        "webdav_hostname": "https://webdav.example.com",
        "webdav_login": "user",
        "webdav_password": "password",
        "webdav_disable_check": True,
    }

    async with (
        aiohttp.ClientSession() as session,
        Client(webdav_options, session=session) as c,
    ):
        yield c
