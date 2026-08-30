"""Remote-only WebDAV client."""

from __future__ import annotations

from typing import TYPE_CHECKING, Self

from ._http import ClientOptions, WebDavHttp
from ._paths import base_path, normalize_path, parent_path, same_path
from ._xml import (
    find_resource,
    lock_body,
    parse_properties,
    parse_property_map,
    parse_quota,
    parse_resources,
    propfind_body,
    proppatch_body,
    quota_body,
)
from .exceptions import (
    ConflictError,
    InvalidResponseError,
    MethodNotSupportedError,
    RemoteParentNotFoundError,
    RemoteResourceNotFoundError,
)

if TYPE_CHECKING:
    import builtins
    from collections.abc import AsyncIterable, AsyncIterator
    from types import TracebackType
    from typing import IO

    from aiohttp import ClientResponse, ClientTimeout

    from ._http import RequestData
    from .models import Property, PropertyRequest, QuotaInfo, ResourceInfo

DEFAULT_ROOT = "/"


async def _iter_content(
    response: ClientResponse,
    chunk_size: int,
) -> AsyncIterator[bytes]:
    """Yield response body chunks."""
    while chunk := await response.content.read(chunk_size):
        yield chunk


class Client:
    """Async WebDAV client for remote resources."""

    def __init__(
        self,
        url: str,
        *,
        username: str = "",
        password: str = "",
        options: ClientOptions | None = None,
    ) -> None:
        """Initialize the client."""
        self._http = WebDavHttp(
            url,
            username=username,
            password=password,
            options=options,
        )
        self._base_path = base_path(url, self._http.options.root)

    @property
    def chunk_size(self) -> int:
        """Return the configured transfer chunk size."""
        return self._http.options.chunk_size

    def url(self, path: str) -> str:
        """Return the absolute URL for a remote path."""
        return self._http.url(path)

    async def request(
        self,
        method: str,
        path: str,
        *,
        data: RequestData = None,
        headers: dict[str, str] | None = None,
        timeout: ClientTimeout | None = None,
        lock_token: str | None = None,
    ) -> ClientResponse:
        """Execute a raw WebDAV request."""
        return await self._http.request(
            method,
            normalize_path(path, directory=path.endswith("/")),
            data=data,
            headers=headers,
            timeout=timeout,
            lock_token=lock_token,
        )

    async def exists(self, path: str = DEFAULT_ROOT) -> bool:
        """Return true if a remote resource exists."""
        try:
            await self.stat(path)
        except RemoteResourceNotFoundError:
            return False
        return True

    async def stat(self, path: str = DEFAULT_ROOT) -> ResourceInfo:
        """Return metadata for one remote resource."""
        remote_path = normalize_path(path, directory=path.endswith("/"))
        response = await self.request(
            "PROPFIND",
            remote_path,
            headers={"Depth": "0"},
        )
        return find_resource(
            await response.read(),
            remote_path,
            self._base_path,
        )

    async def is_dir(self, path: str = DEFAULT_ROOT) -> bool:
        """Return true if a remote resource is a directory."""
        return (await self.stat(path)).is_dir

    async def list(
        self,
        path: str = DEFAULT_ROOT,
        *,
        recursive: bool = False,
    ) -> builtins.list[ResourceInfo]:
        """List child resources under a remote directory."""
        remote_path = normalize_path(path, directory=True)
        response = await self.request(
            "PROPFIND",
            remote_path,
            headers={"Depth": "infinity" if recursive else "1"},
        )
        resources = parse_resources(await response.read(), self._base_path)
        return [item for item in resources if not same_path(item.path, remote_path)]

    async def mkdir(
        self,
        path: str,
        *,
        parents: bool = False,
        exist_ok: bool = False,
    ) -> None:
        """Create a remote directory."""
        remote_path = normalize_path(path, directory=True)
        if parents:
            await self._mkdir_parents(remote_path)

        try:
            response = await self.request("MKCOL", remote_path)
            response.release()
        except MethodNotSupportedError:
            if exist_ok and await self.exists(remote_path):
                return
            raise
        except ConflictError as err:
            if not await self.exists(parent_path(remote_path)):
                raise RemoteParentNotFoundError(remote_path) from err
            raise

    async def _mkdir_parents(self, path: str) -> None:
        parents: builtins.list[str] = []
        current = parent_path(path)
        while current != "/":
            parents.append(current)
            current = parent_path(current.rstrip("/"))

        for item in reversed(parents):
            try:
                await self.mkdir(item, exist_ok=True)
            except MethodNotSupportedError:
                if not await self.exists(item):
                    raise

    async def delete(self, path: str, *, lock_token: str | None = None) -> None:
        """Delete a remote resource."""
        response = await self.request(
            "DELETE",
            normalize_path(path, directory=path.endswith("/")),
            lock_token=lock_token,
        )
        response.release()

    async def copy(
        self,
        source: str,
        target: str,
        *,
        depth: int | str | None = None,
        overwrite: bool = True,
        lock_token: str | None = None,
    ) -> None:
        """Copy a remote resource."""
        headers = {
            "Destination": self.url(target),
            "Overwrite": "T" if overwrite else "F",
        }
        if depth is not None:
            headers["Depth"] = str(depth)
        response = await self.request(
            "COPY",
            normalize_path(source, directory=source.endswith("/")),
            headers=headers,
            lock_token=lock_token,
        )
        response.release()

    async def move(
        self,
        source: str,
        target: str,
        *,
        overwrite: bool = False,
        lock_token: str | None = None,
    ) -> None:
        """Move a remote resource."""
        response = await self.request(
            "MOVE",
            normalize_path(source, directory=source.endswith("/")),
            headers={
                "Destination": self.url(target),
                "Overwrite": "T" if overwrite else "F",
            },
            lock_token=lock_token,
        )
        response.release()

    async def read(
        self,
        path: str,
        *,
        timeout: ClientTimeout | None = None,
    ) -> bytes:
        """Read a remote resource into memory."""
        response = await self.request("GET", normalize_path(path), timeout=timeout)
        return await response.read()

    async def iter_read(
        self,
        path: str,
        *,
        timeout: ClientTimeout | None = None,
    ) -> AsyncIterator[bytes]:
        """Stream a remote resource."""
        response = await self.request("GET", normalize_path(path), timeout=timeout)
        try:
            async for chunk in _iter_content(response, self.chunk_size):
                yield chunk
        finally:
            response.release()

    async def write(
        self,
        path: str,
        data: RequestData,
        *,
        content_length: int | None = None,
        timeout: ClientTimeout | None = None,
        lock_token: str | None = None,
    ) -> None:
        """Write data to a remote resource."""
        remote_path = normalize_path(path)
        headers: dict[str, str] = {}
        if content_length is not None:
            headers["Content-Length"] = str(content_length)

        try:
            response = await self.request(
                "PUT",
                remote_path,
                data=data,
                headers=headers,
                timeout=timeout,
                lock_token=lock_token,
            )
            response.release()
        except ConflictError as err:
            if not await self.exists(parent_path(remote_path)):
                raise RemoteParentNotFoundError(remote_path) from err
            raise

    async def quota(self) -> QuotaInfo:
        """Return RFC 4331 quota information."""
        response = await self.request(
            "PROPFIND",
            "/",
            data=quota_body(),
            headers={"Depth": "0", "Content-Type": "text/xml"},
        )
        return parse_quota(await response.read(), self._http.base_url)

    async def get_property(
        self,
        path: str,
        requested_property: PropertyRequest,
    ) -> Property | None:
        """Return one remote property value."""
        properties = await self.get_properties(path, [requested_property])
        return properties[0] if properties else None

    async def get_properties(
        self,
        path: str,
        requested_properties: builtins.list[PropertyRequest],
    ) -> builtins.list[Property]:
        """Return remote property values."""
        response = await self.request(
            "PROPFIND",
            normalize_path(path, directory=path.endswith("/")),
            data=propfind_body(requested_properties),
            headers={"Depth": "0", "Content-Type": "text/xml"},
        )
        return parse_properties(await response.read(), requested_properties)

    async def list_properties(
        self,
        path: str = DEFAULT_ROOT,
        *,
        properties: builtins.list[PropertyRequest],
    ) -> dict[str, builtins.list[Property]]:
        """Return requested properties for children under a remote directory."""
        response = await self.request(
            "PROPFIND",
            normalize_path(path, directory=True),
            data=propfind_body(properties),
            headers={"Depth": "1", "Content-Type": "text/xml"},
        )
        return parse_property_map(await response.read(), properties, self._base_path)

    async def set_property(self, path: str, prop: Property) -> None:
        """Set one remote property."""
        await self.set_properties(path, [prop])

    async def set_properties(
        self, path: str, properties: builtins.list[Property]
    ) -> None:
        """Set remote properties."""
        response = await self.request(
            "PROPPATCH",
            normalize_path(path, directory=path.endswith("/")),
            data=proppatch_body(properties),
            headers={"Depth": "0", "Content-Type": "text/xml"},
        )
        response.release()

    async def lock(
        self,
        path: str = DEFAULT_ROOT,
        *,
        timeout: int | None = None,
    ) -> Lock:
        """Create an exclusive write lock."""
        headers = {"Timeout": f"Second-{timeout}"} if timeout else None
        remote_path = normalize_path(path, directory=path.endswith("/"))
        response = await self.request(
            "LOCK",
            remote_path,
            data=lock_body(),
            headers=headers,
        )
        if "Lock-Token" not in response.headers:
            try:
                raise InvalidResponseError(
                    self.url(remote_path),
                    "LOCK response is missing Lock-Token header",
                )
            finally:
                response.release()
        token = response.headers["Lock-Token"]
        response.release()
        return Lock(self, remote_path, token)

    async def unlock(self, path: str, token: str) -> None:
        """Unlock a remote resource."""
        response = await self.request("UNLOCK", path, headers={"Lock-Token": token})
        response.release()

    async def close(self) -> None:
        """Close the owned HTTP session."""
        await self._http.close()

    async def __aenter__(self) -> Self:
        """Enter the async context manager."""
        return self

    async def __aexit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        """Exit the async context manager."""
        await self.close()


class Lock:
    """Async context manager for a WebDAV lock."""

    def __init__(self, client: Client, path: str, token: str) -> None:
        """Initialize a lock handle."""
        self.client = client
        self.path = path
        self.token = token

    async def __aenter__(self) -> Self:
        """Enter the lock context."""
        return self

    async def __aexit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        """Unlock the remote resource."""
        await self.client.unlock(self.path, self.token)

    async def read(self) -> bytes:
        """Read the locked resource."""
        return await self.client.read(self.path)

    async def iter_read(self) -> AsyncIterator[bytes]:
        """Stream the locked resource."""
        async for chunk in self.client.iter_read(self.path):
            yield chunk

    async def write(
        self,
        data: bytes | str | IO[bytes] | AsyncIterable[bytes],
        *,
        content_length: int | None = None,
    ) -> None:
        """Write to the locked resource."""
        await self.client.write(
            self.path,
            data,
            content_length=content_length,
            lock_token=self.token,
        )
