"""HTTP transport for WebDAV requests."""

from base64 import b64encode
from collections.abc import AsyncIterable
from dataclasses import dataclass
from typing import IO

from aiohttp import (
    ClientConnectionError,
    ClientResponse,
    ClientResponseError,
    ClientSession,
    ClientTimeout,
)
from aiohttp.client import DEFAULT_TIMEOUT

from ._paths import join_url
from .exceptions import (
    AccessDeniedError,
    ConflictError,
    ConnectionExceptionError,
    MethodNotSupportedError,
    NoConnectionError,
    NotEnoughSpaceError,
    RemoteResourceNotFoundError,
    ResourceLockedError,
    ResponseErrorCodeError,
    UnauthorizedError,
)

RequestData = (
    bytes
    | str
    | IO[bytes]
    | AsyncIterable[bytes]
    | list[tuple[str, str | int | bool]]
    | None
)


@dataclass(frozen=True, slots=True, kw_only=True)
class ClientOptions:
    """Client options for WebDAV client."""

    session: ClientSession | None = None
    timeout: ClientTimeout | None = DEFAULT_TIMEOUT
    verify_ssl: bool = True
    root: str = "/"
    chunk_size: int = 65536
    token: str | None = None
    proxy: str | None = None
    proxy_headers: dict[str, str] | None = None


class WebDavHttp:
    """Small aiohttp wrapper for WebDAV requests."""

    def __init__(
        self,
        base_url: str,
        *,
        username: str = "",
        password: str = "",
        options: ClientOptions | None = None,
    ) -> None:
        """Initialize the HTTP transport."""
        self.base_url = base_url
        self.username = username
        self.password = password
        self.options = options or ClientOptions()
        self.session = self.options.session
        self._owns_session = self.options.session is None

    def url(self, path: str) -> str:
        """Return the absolute URL for a remote path."""
        return join_url(self.base_url, self.options.root, path)

    def headers(
        self,
        headers: dict[str, str] | None = None,
        *,
        lock_token: str | None = None,
    ) -> dict[str, str]:
        """Build request headers."""
        result = {"Accept": "*/*"}
        if headers:
            result.update(headers)

        if self.options.token:
            result["Authorization"] = f"Bearer {self.options.token}"
        elif basic_auth := self._basic_auth_header():
            result["Authorization"] = basic_auth

        if lock_token:
            result["If"] = f"({lock_token})"
        return result

    def _basic_auth_header(self) -> str | None:
        if self.options.token:
            return None
        if not self.username or not self.password:
            return None
        if ":" in self.username:
            msg = 'A ":" is not allowed in username'
            raise ValueError(msg)
        token = b64encode(f"{self.username}:{self.password}".encode()).decode()
        return f"Basic {token}"

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
        """Execute a WebDAV request."""
        url = self.url(path)
        try:
            response = await self._session().request(
                method=method,
                url=url,
                headers=self.headers(headers, lock_token=lock_token),
                timeout=timeout or self.options.timeout,
                ssl=self.options.verify_ssl,
                data=data,
                proxy=self.options.proxy,
                proxy_headers=self.options.proxy_headers,
            )
        except ClientConnectionError as err:
            raise NoConnectionError(self.base_url) from err
        except ClientResponseError as err:
            raise ConnectionExceptionError(err) from err

        await self._raise_for_status(response, path)
        return response

    async def _raise_for_status(self, response: ClientResponse, path: str) -> None:
        if response.status == 401:
            raise UnauthorizedError(self.base_url)
        if response.status == 403:
            raise AccessDeniedError(self.base_url)
        if response.status == 404:
            raise RemoteResourceNotFoundError(path=path)
        if response.status == 405:
            raise MethodNotSupportedError(name=response.method, server=self.base_url)
        if response.status == 409:
            raise ConflictError(path=path, message=await response.text())
        if response.status == 423:
            raise ResourceLockedError(path=path)
        if response.status == 507:
            raise NotEnoughSpaceError
        if response.status >= 400:
            raise ResponseErrorCodeError(
                url=self.url(path),
                code=response.status,
                message=await response.text(),
            )

    def _session(self) -> ClientSession:
        """Return an open session, creating the owned session lazily."""
        if self.session is None:
            self.session = ClientSession()
        return self.session

    async def close(self) -> None:
        """Close the owned session."""
        if self._owns_session and self.session is not None:
            await self.session.close()
