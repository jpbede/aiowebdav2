"""Local filesystem helpers for WebDAV transfers."""

import asyncio
from collections.abc import AsyncIterable, Awaitable, Callable, Coroutine, Iterable
import inspect
from pathlib import Path
from posixpath import relpath
import shutil
from typing import Any, cast

import aiofiles
import aiofiles.os

from ._paths import normalize_path, parent_path
from .client import Client
from .exceptions import LocalResourceNotFoundError, OptionNotValidError

ProgressCallback = Callable[[int, int | None], None | Awaitable[None]]
_Rglob = Callable[[Path], Awaitable[list[Path]]]
_Rmtree = Callable[[Path], Awaitable[None]]


def _sync_rglob(path: Path) -> list[Path]:
    return list(path.rglob("*"))


_async_rglob = cast("_Rglob", aiofiles.os.wrap(_sync_rglob))
_async_rmtree = cast("_Rmtree", aiofiles.os.wrap(shutil.rmtree))


async def _call_progress(
    progress: ProgressCallback | None,
    current: int,
    total: int | None,
) -> None:
    if progress is None:
        return
    result = progress(current, total)
    if inspect.isawaitable(result):
        await result


async def download_file(
    client: Client,
    remote_path: str,
    local_path: Path,
    *,
    progress: ProgressCallback | None = None,
) -> None:
    """Download one remote file to a local path."""
    if await aiofiles.os.path.isdir(local_path):
        raise OptionNotValidError(name="local_path", value=str(local_path))

    response = await client.request("GET", normalize_path(remote_path))
    try:
        content_length = response.headers.get("content-length")
        total = int(content_length) if content_length is not None else None
        current = 0
        await _call_progress(progress, current, total)

        await aiofiles.os.makedirs(local_path.parent, exist_ok=True)
        async with aiofiles.open(local_path, "wb") as local_file:
            while chunk := await response.content.read(client.chunk_size):
                await local_file.write(chunk)
                current += len(chunk)
                await _call_progress(progress, current, total)
    finally:
        response.release()


async def upload_file(
    client: Client,
    local_path: Path,
    remote_path: str,
    *,
    parents: bool = False,
    progress: ProgressCallback | None = None,
) -> None:
    """Upload one local file to a remote path."""
    if not await aiofiles.os.path.exists(local_path):
        raise LocalResourceNotFoundError(str(local_path))
    if await aiofiles.os.path.isdir(local_path):
        raise OptionNotValidError(name="local_path", value=str(local_path))

    if parents:
        parent = parent_path(remote_path)
        if parent != "/":
            await client.mkdir(parent, parents=True, exist_ok=True)

    total = (await aiofiles.os.stat(local_path)).st_size

    async def chunks() -> AsyncIterable[bytes]:
        current = 0
        await _call_progress(progress, current, total)
        async with aiofiles.open(local_path, "rb") as local_file:
            while chunk := await local_file.read(client.chunk_size):
                current += len(chunk)
                yield chunk
                await _call_progress(progress, current, total)

    await client.write(remote_path, chunks(), content_length=total)


async def download_tree(
    client: Client,
    remote_path: str,
    local_path: Path,
    *,
    overwrite: bool = False,
    concurrency: int = 1,
    progress: ProgressCallback | None = None,
) -> None:
    """Download a remote directory tree."""
    if concurrency < 1:
        raise OptionNotValidError(name="concurrency", value=str(concurrency))

    if await aiofiles.os.path.exists(local_path):
        if not await aiofiles.os.path.isdir(local_path):
            raise OptionNotValidError(name="local_path", value=str(local_path))
        if not overwrite:
            msg = f"Local directory already exists: {local_path}"
            raise FileExistsError(msg)
        await _rmtree(local_path)

    await aiofiles.os.makedirs(local_path)
    remote_root = normalize_path(remote_path, directory=True)
    resources = await client.list(remote_root, recursive=True)

    for resource in resources:
        relative_path = _relative_resource_path(
            resource.path,
            remote_root,
            directory=resource.is_dir,
        )
        if resource.is_dir:
            await aiofiles.os.makedirs(local_path / relative_path, exist_ok=True)

    semaphore = asyncio.Semaphore(concurrency)

    async def download_one(path: str) -> None:
        async with semaphore:
            target = local_path / _relative_resource_path(path, remote_root)
            await download_file(client, path, target, progress=progress)

    await _gather_transfer_tasks(
        download_one(resource.path) for resource in resources if not resource.is_dir
    )


def _relative_resource_path(
    path: str,
    remote_root: str,
    *,
    directory: bool = False,
) -> str:
    normalized_path = normalize_path(path, directory=directory)
    normalized_root = normalize_path(remote_root, directory=True)
    if "\\" in normalized_path:
        raise OptionNotValidError(name="remote_path", value=path)
    if normalized_path == normalized_root:
        return "."
    if not normalized_path.startswith(normalized_root):
        raise OptionNotValidError(name="remote_path", value=path)
    return relpath(normalized_path, normalized_root)


async def upload_tree(
    client: Client,
    local_path: Path,
    remote_path: str,
    *,
    concurrency: int = 1,
    progress: ProgressCallback | None = None,
) -> None:
    """Upload a local directory tree."""
    if concurrency < 1:
        raise OptionNotValidError(name="concurrency", value=str(concurrency))
    if not await aiofiles.os.path.exists(local_path):
        raise LocalResourceNotFoundError(str(local_path))
    if not await aiofiles.os.path.isdir(local_path):
        raise OptionNotValidError(name="local_path", value=str(local_path))

    remote_root = normalize_path(remote_path, directory=True)
    await client.mkdir(remote_root, parents=True, exist_ok=True)

    local_resources = await _rglob(local_path)
    directories: list[Path] = []
    files: list[Path] = []
    for path in local_resources:
        if await aiofiles.os.path.isdir(path):
            directories.append(path)
        elif await aiofiles.os.path.isfile(path):
            files.append(path)

    directories = sorted(
        directories,
        key=lambda path: len(path.relative_to(local_path).parts),
    )
    for directory in directories:
        target = f"{remote_root}{directory.relative_to(local_path).as_posix()}/"
        await client.mkdir(target, exist_ok=True)

    semaphore = asyncio.Semaphore(concurrency)

    async def upload_one(path: Path) -> None:
        async with semaphore:
            target = f"{remote_root}{path.relative_to(local_path).as_posix()}"
            await upload_file(client, path, target, progress=progress)

    await _gather_transfer_tasks(upload_one(path) for path in files)


async def _gather_transfer_tasks(coros: Iterable[Coroutine[Any, Any, None]]) -> None:
    tasks: list[asyncio.Task[None]] = [asyncio.create_task(coro) for coro in coros]
    if not tasks:
        return
    try:
        await asyncio.gather(*tasks)
    except Exception:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise


async def _rglob(path: Path) -> list[Path]:
    return await _async_rglob(path)


async def _rmtree(path: Path) -> None:
    await _async_rmtree(path)
