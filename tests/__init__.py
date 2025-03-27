"""Helpers for the tests."""

from collections.abc import AsyncGenerator
from pathlib import Path


def load_responses(filename: str) -> str:
    """Load a responses."""
    path = Path(__file__).parent / "responses" / filename
    return path.read_text()


async def upload_stream() -> AsyncGenerator[bytes, None]:
    """Generate a stream of bytes."""
    yield b"Hello, "
    yield b"world!"
