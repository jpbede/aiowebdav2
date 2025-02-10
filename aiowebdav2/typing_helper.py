"""Typing definitions for aiowebdav2."""

from typing import Protocol


class AsyncWriteBuffer(Protocol):
    """Protocol for async write buffer."""

    async def write(self, data: bytes) -> None:
        """Write data to buffer."""
