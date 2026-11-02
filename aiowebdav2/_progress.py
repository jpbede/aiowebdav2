"""Transfer progress helpers."""

from collections.abc import AsyncIterable, AsyncIterator, Awaitable, Callable
import inspect

ProgressCallback = Callable[[int, int | None], Awaitable[None] | None]


async def call_progress(
    progress: ProgressCallback | None,
    current: int,
    total: int | None,
) -> None:
    """Call a sync or async progress callback."""
    if progress is None:
        return
    result = progress(current, total)
    if inspect.isawaitable(result):
        await result


async def with_progress(
    data: AsyncIterable[bytes],
    progress: ProgressCallback,
    total: int | None,
) -> AsyncIterator[bytes]:
    """Yield chunks and report the bytes handed off after each chunk."""
    current = 0
    await call_progress(progress, current, total)
    async for chunk in data:
        current += len(chunk)
        yield chunk
        await call_progress(progress, current, total)
