"""Fixtures for aiowebdav2 tests."""

from collections.abc import AsyncGenerator, Generator

import aiohttp
from aioresponses import aioresponses
import pytest

from aiowebdav2 import Client
from aiowebdav2.client import ClientOptions
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
    async with (
        aiohttp.ClientSession() as session,
        Client(
            url="https://webdav.example.com",
            username="user",
            password="password",
            options=ClientOptions(session=session, disable_check=True),
        ) as c,
    ):
        yield c
