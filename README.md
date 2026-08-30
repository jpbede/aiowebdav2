# aiowebdav2

`aiowebdav2` is a typed asyncio WebDAV client for Python 3.13+.

## Installation

```bash
pip install aiowebdav2
```

## Remote API

The `Client` API is remote-only. It exposes WebDAV resources as paths and does
not read from or write to the local filesystem.

```python
import asyncio

from aiowebdav2 import Client


async def main() -> None:
    async with Client(
        "https://webdav.example.com/remote.php/dav/files/me/",
        username="me",
        password="secret",
    ) as client:
        await client.mkdir("/docs/", parents=True, exist_ok=True)
        await client.write("/docs/readme.txt", b"hello")

        info = await client.stat("/docs/readme.txt")
        print(info.path, info.size)

        for child in await client.list("/docs/"):
            print(child.path, child.is_dir)

        data = await client.read("/docs/readme.txt")
        print(data)


asyncio.run(main())
```

Main remote operations:

- `exists(path) -> bool`
- `stat(path) -> ResourceInfo`
- `is_dir(path) -> bool`
- `list(path="/", recursive=False) -> list[ResourceInfo]`
- `mkdir(path, parents=False, exist_ok=False) -> None`
- `delete(path) -> None`
- `copy(source, target, depth=None, overwrite=True) -> None`
- `move(source, target, overwrite=False) -> None`
- `read(path) -> bytes`
- `iter_read(path) -> AsyncIterator[bytes]`
- `write(path, data, content_length=None) -> None`
- `quota() -> QuotaInfo`
- `get_property(path, property_request) -> Property | None`
- `get_properties(path, property_requests) -> list[Property]`
- `list_properties(path, properties=...) -> dict[str, list[Property]]`
- `set_property(path, property) -> None`
- `set_properties(path, properties) -> None`
- `lock(path) -> Lock`

## Filesystem Helpers

Local file transfer helpers live in `aiowebdav2.filesystem`. They depend on a
`Client`, but the client does not depend on local paths.

```python
from pathlib import Path
import asyncio

from aiowebdav2 import Client
from aiowebdav2.filesystem import download_file, download_tree, upload_file, upload_tree


async def main() -> None:
    async with Client(
        "https://webdav.example.com",
        username="me",
        password="secret",
    ) as client:
        await upload_file(client, Path("readme.txt"), "/docs/readme.txt", parents=True)
        await download_file(client, "/docs/readme.txt", Path("readme.txt"))
        await upload_tree(client, Path("docs"), "/docs/", concurrency=4)
        await download_tree(client, "/docs/", Path("docs"), concurrency=4)


asyncio.run(main())
```

Filesystem helper operations:

- `download_file(client, remote_path, local_path, progress=None) -> None`
- `upload_file(client, local_path, remote_path, parents=False, progress=None) -> None`
- `download_tree(client, remote_path, local_path, overwrite=False, concurrency=1, progress=None) -> None`
- `upload_tree(client, local_path, remote_path, concurrency=1, progress=None) -> None`

Progress callbacks receive `(current_bytes, total_bytes | None)` and may be
sync or async callables.

## Authentication

Pass `username` and `password`, or a bearer token in `ClientOptions`.

```python
import asyncio

from aiowebdav2 import Client, ClientOptions


async def main() -> None:
    async with Client(
        "https://webdav.example.com",
        username="me",
        password="secret",
    ) as client:
        await client.list("/")

    async with Client(
        "https://webdav.example.com",
        options=ClientOptions(token="token"),
    ) as client:
        await client.list("/")


asyncio.run(main())
```

## Sessions and Options

`Client` owns its aiohttp session unless an external session is passed.

```python
import asyncio

from aiohttp import ClientSession, ClientTimeout

from aiowebdav2 import Client, ClientOptions


async def main() -> None:
    async with ClientSession() as session:
        client = Client(
            "https://webdav.example.com",
            options=ClientOptions(
                session=session,
                timeout=ClientTimeout(total=30),
                verify_ssl=True,
                root="/",
                chunk_size=65536,
                proxy="http://127.0.0.1:8080",
                proxy_headers={"Proxy-Authorization": "Basic ..."},
            ),
        )


asyncio.run(main())
```

## Models

```python
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True, kw_only=True)
class ResourceInfo:
    path: str
    name: str
    is_dir: bool
    size: int | None = None
    modified: datetime | None = None
    created: datetime | None = None
    etag: str | None = None
    content_type: str | None = None
```

`Property`, `PropertyRequest`, and `QuotaInfo` are also frozen, slotted
dataclasses.

## Development

```bash
uv sync --group dev
uv run pytest --cov-report=term-missing
uv run ruff check .
uv run ruff format --check .
uv run mypy aiowebdav2
```
