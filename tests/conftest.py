"""Fixtures for aiowebdav2 tests."""

from collections.abc import AsyncGenerator, Generator

import aiohttp
from aioresponses import aioresponses
import pytest

from aiowebdav2 import Client


@pytest.fixture(name="responses")
def aioresponses_fixture() -> Generator[aioresponses, None, None]:
    """Return aioresponses fixture."""
    with aioresponses() as mocked_responses:
        yield mocked_responses


@pytest.fixture(name="client")
async def client() -> AsyncGenerator[Client, None]:
    """Return a aiowebdav2 client."""
    options = {
        "webdav_hostname": "https://webdav.example.com",
        "webdav_login": "user",
        "webdav_password": "password",
        "webdav_disable_check": True,
    }

    async with (
        aiohttp.ClientSession() as session,
        Client(options, session=session) as c,
    ):
        yield c
