"""WebDAV client implementation."""

import asyncio
from collections.abc import AsyncIterable, AsyncIterator, Awaitable, Callable, Coroutine
from dataclasses import dataclass
import logging
from pathlib import Path
from re import sub
import shutil
from typing import IO, Any, ClassVar, Self
from urllib.parse import unquote

import aiofiles
from aiohttp import (
    BasicAuth,
    ClientConnectionError,
    ClientResponse,
    ClientResponseError,
    ClientSession,
    ClientTimeout,
)
from aiohttp.client import DEFAULT_TIMEOUT
from dateutil.parser import parse as dateutil_parse
import yarl

from .exceptions import (
    ConnectionExceptionError,
    LocalResourceNotFoundError,
    MethodNotSupportedError,
    NoConnectionError,
    NotEnoughSpaceError,
    OptionNotValidError,
    RemoteParentNotFoundError,
    RemoteResourceNotFoundError,
    ResourceLockedError,
    ResponseErrorCodeError,
    UnauthorizedError,
)
from .models import Property, PropertyRequest
from .parser import WebDavXmlUtils
from .typing_helper import AsyncWriteBuffer
from .urn import Urn

_LOGGER = logging.getLogger(__name__)

CONST_ACCEPT_ALL = "Accept: */*"
CONST_DEPTH_1 = "Depth: 1"
CONST_DEPTH_0 = "Depth: 0"
DEFAULT_ROOT = "/"


async def _iter_content(
    response: ClientResponse, chunk_size: int
) -> AsyncIterator[bytes]:
    """Async generator to iterate over response content by chunks."""
    while chunk := await response.content.read(chunk_size):
        yield chunk


@dataclass(frozen=True, slots=True, kw_only=True)
class ClientOptions:
    """Client options for WebDAV client."""

    send_speed: int | None = None
    recv_speed: int | None = None
    session: ClientSession | None = None
    timeout: ClientTimeout | None = DEFAULT_TIMEOUT
    verify_ssl: bool = True
    root: str = "/"
    chunk_size: int = 65536
    disable_check: bool = False
    token: str | None = None
    proxy: str | None = None
    proxy_auth: BasicAuth | None = None


class Client:
    """The client for WebDAV servers provides an ability to control files on remote WebDAV server."""

    # HTTP headers for different actions
    default_http_header: ClassVar[dict[str, list[str]]] = {
        "list": [CONST_ACCEPT_ALL, CONST_DEPTH_1],
        "free": [CONST_ACCEPT_ALL, CONST_DEPTH_0, "Content-Type: text/xml"],
        "copy": [CONST_ACCEPT_ALL],
        "move": [CONST_ACCEPT_ALL],
        "mkdir": [CONST_ACCEPT_ALL, "Connection: Keep-Alive"],
        "clean": [CONST_ACCEPT_ALL, "Connection: Keep-Alive"],
        "check": [CONST_ACCEPT_ALL],
        "info": [CONST_ACCEPT_ALL, CONST_DEPTH_1],
        "get_property": [
            CONST_ACCEPT_ALL,
            CONST_DEPTH_0,
            "Content-Type: application/x-www-form-urlencoded",
        ],
        "set_property": [
            CONST_ACCEPT_ALL,
            CONST_DEPTH_0,
            "Content-Type: application/x-www-form-urlencoded",
        ],
    }

    # mapping of actions to WebDAV methods
    default_requests: ClassVar[dict[str, str]] = {
        "options": "OPTIONS",
        "download": "GET",
        "upload": "PUT",
        "copy": "COPY",
        "move": "MOVE",
        "mkdir": "MKCOL",
        "clean": "DELETE",
        "check": "HEAD",
        "list": "PROPFIND",
        "free": "PROPFIND",
        "info": "PROPFIND",
        "publish": "PROPPATCH",
        "unpublish": "PROPPATCH",
        "published": "PROPPATCH",
        "get_property": "PROPFIND",
        "set_property": "PROPPATCH",
        "lock": "LOCK",
        "unlock": "UNLOCK",
    }

    meta_xmlns: ClassVar[dict[str, str]] = {
        "https://webdav.yandex.ru": "urn:yandex:disk:meta",
    }

    _close_session: bool = False

    def __init__(
        self,
        url: str,
        username: str,
        password: str,
        *,
        options: ClientOptions | None = None,
    ) -> None:
        """Construct a WebDAV client.

        :param url: the URL of the WebDAV server.
        :param username: the username for the WebDAV server.
        :param password: the password for the WebDAV server.
        :param options: the options for the WebDAV client.
        """
        self._url = url
        self._username = username
        self._password = password
        self._options = options or ClientOptions()

        self._session = (
            self._options.session if self._options.session else ClientSession()
        )
        self._close_session = not bool(self._options.session)
        self.http_header = self.default_http_header.copy()
        self.requests = self.default_requests.copy()

    def get_headers(
        self, action: str, headers_ext: list[str] | None = None
    ) -> dict[str, str]:
        """Return HTTP headers of specified WebDAV actions.

        :param action: the identifier of action.
        :param headers_ext: (optional) the addition headers list witch sgould be added to basic HTTP headers for
                            the specified action.
        :return: the dictionary of headers for specified action.
        """
        if action in self.http_header:
            try:
                headers = self.http_header[action].copy()
            except AttributeError:
                headers = self.http_header[action][:]
        else:
            headers = []

        if headers_ext:
            headers.extend(headers_ext)

        if self._options.token:
            webdav_token = f"Authorization: Bearer {self._options.token}"
            headers.append(webdav_token)

        return dict([i.split(":", 1) for i in headers])

    def get_url(self, path: str) -> str:
        """Generate url by uri path.

        :param path: uri path.
        :return: the url string.
        """
        path = path.lstrip(Urn.separate)
        root = self._options.root.lstrip(Urn.separate)
        return str(yarl.URL(self._url).joinpath(root, path))

    def get_full_path(self, urn: Urn) -> str:
        """Generate full path to remote resource exclude hostname.

        :param urn: the URN to resource.
        :return: full path to resource with root path.
        """
        return f"{unquote(self._options.root)}{urn.path()}"

    async def execute_request(
        self,
        action: str,
        path: str,
        data: list[tuple[str, str | int | bool]]
        | bytes
        | AsyncIterable[bytes]
        | AsyncWriteBuffer
        | IO[bytes]
        | str
        | None = None,
        headers_ext: list[str] | None = None,
        *,
        timeout: ClientTimeout | None = None,
    ) -> ClientResponse:
        """Generate request to WebDAV server for specified action and path and execute it.

        :param action: the action for WebDAV server which should be executed.
        :param path: the path to resource for action
        :param data: (optional) Dictionary or list of tuples ``[(key, value)]`` (will be form-encoded), bytes,
                     or file-like object to send in the body of the :class:`Request`.
        :param headers_ext: (optional) the addition headers list witch should be added to basic HTTP headers for
                            the specified action.
        :param timeout: (optional) the timeout for the request.
        :return: HTTP response of request.
        """
        url = self.get_url(path)
        method = self.requests[action]

        _LOGGER.debug("Request to %s with method %s", url, method)

        try:
            response = await self._session.request(
                method=method,
                url=url,
                auth=BasicAuth(self._username, self._password)
                if (not self._options.token and not self._session.auth)
                and (self._username and self._password)
                else None,
                headers=self.get_headers(action, headers_ext),
                timeout=timeout or self._options.timeout,
                ssl=self._options.verify_ssl,
                data=data,
                proxy=self._options.proxy,
                proxy_auth=self._options.proxy_auth,
            )
        except ClientConnectionError as err:
            raise NoConnectionError(self._url) from err
        except ClientResponseError as re:
            raise ConnectionExceptionError(re) from re

        _LOGGER.debug("Got response with status: %s", response.status)

        if response.status == 401:
            raise UnauthorizedError(self._url)
        if response.status == 507:
            raise NotEnoughSpaceError
        if response.status == 404:
            raise RemoteResourceNotFoundError(path=path)
        if response.status == 423:
            raise ResourceLockedError(path=path)
        if response.status == 405:
            raise MethodNotSupportedError(name=action, server=self._url)
        if response.status >= 400:
            raise ResponseErrorCodeError(
                url=self.get_url(path),
                code=response.status,
                message=str(await response.read()),
            )

        return response

    async def list_files(
        self,
        remote_path: str = DEFAULT_ROOT,
        *,
        recursive: bool = False,
    ) -> list[str]:
        """Return list of nested files and directories for remote WebDAV directory by path.

        More information you can find by link https://www.rfc-editor.org/rfc/rfc4918.html#section-9.1.

        :param remote_path: path to remote directory.
        :param recursive: true will do a recursive listing of infinite depth
        :return: if get_info=False it returns list of nested file or directory names, otherwise it returns
                 list of information, the information is a dictionary and it values with following keys:
                 `created`: date of resource creation,
                 `name`: name of resource,
                 `size`: size of resource,
                 `modified`: date of resource modification,
                 `etag`: etag of resource,
                 `content_type`: content type of resource,
                 `isdir`: type of resource,
                 `path`: path of resource.

        """
        headers = []
        if recursive is True:
            headers = ["Depth:infinity"]
        directory_urn = Urn(remote_path, directory=True)
        if directory_urn.path() != DEFAULT_ROOT and not await self.check(
            directory_urn.path()
        ):
            raise RemoteResourceNotFoundError(directory_urn.path())

        path = Urn.normalize_path(self.get_full_path(directory_urn))
        response = await self.execute_request(
            action="list", path=directory_urn.quote(), headers_ext=headers
        )
        urns = WebDavXmlUtils.parse_get_list_response(await response.read())

        return [
            urn.filename()
            for urn in urns
            if Urn.compare_path(path, urn.path()) is False
        ]

    async def list_with_infos(
        self, remote_path: str = DEFAULT_ROOT, *, recursive: bool = False
    ) -> list[dict[str, str]]:
        """Return list of nested files and directories for remote WebDAV directory by path with additional information.

        More information you can find by link https://www.rfc-editor.org/rfc/rfc4918.html#section-9.1.

        :param remote_path: path to remote directory.
        :param recursive: true will do a recursive listing of infinite depth
        :return: list of information, the information is a dictionary and it values with following
                    keys: `created`: date of resource creation, `name`: name of resource, `size`: size of resource,
                    `modified`: date of resource modification, `etag`: etag of resource, `content_type`: content type of
                    resource, `isdir`: type of resource, `path`: path of resource.
        """
        headers = []
        if recursive is True:
            headers = ["Depth:infinity"]
        directory_urn = Urn(remote_path, directory=True)
        if directory_urn.path() != DEFAULT_ROOT and not await self.check(
            directory_urn.path()
        ):
            raise RemoteResourceNotFoundError(directory_urn.path())

        path = Urn.normalize_path(self.get_full_path(directory_urn))
        response = await self.execute_request(
            action="list", path=directory_urn.quote(), headers_ext=headers
        )
        subfiles = WebDavXmlUtils.parse_get_list_info_response(await response.read())
        return [
            subfile
            for subfile in subfiles
            if Urn.compare_path(path, str(subfile.get("path", ""))) is False
        ]

    async def list_with_properties(
        self,
        remote_path: str = DEFAULT_ROOT,
        properties: list[PropertyRequest] | None = None,
    ) -> dict[str, list[Property]]:
        """Return list of nested files and directories for remote WebDAV directory by path with additional properties.

        More information you can find by link https://www.rfc-editor.org/rfc/rfc4918.html
        """
        if properties is None:
            properties = []

        directory_urn = Urn(remote_path, directory=True)
        if directory_urn.path() != DEFAULT_ROOT and not await self.check(
            directory_urn.path()
        ):
            raise RemoteResourceNotFoundError(directory_urn.path())

        data = WebDavXmlUtils.create_get_property_batch_request_content(properties)
        response = await self.execute_request(
            action="list", path=directory_urn.quote(), data=data
        )
        return WebDavXmlUtils.parse_get_list_property_response(
            await response.read(), properties=properties, hostname=self._url
        )

    async def free(self) -> int | None:
        """Return an amount of free space on remote WebDAV server.

        More information you can find by link https://www.rfc-editor.org/rfc/rfc4918.html#section-9.1.

        :return: an amount of free space in bytes.
        """
        data = WebDavXmlUtils.create_free_space_request_content()
        response = await self.execute_request(action="free", path="", data=data)
        return WebDavXmlUtils.parse_free_space_response(
            await response.read(), self._url
        )

    async def check(self, remote_path: str = DEFAULT_ROOT) -> bool:
        """Check an existence of remote resource on WebDAV server by remote path.

        More information you can find by link https://www.rfc-editor.org/rfc/rfc4918.html#section-9.1.

        :param remote_path: (optional) path to resource on WebDAV server. Defaults is root directory of WebDAV.
        :return: True if resource is exist or False otherwise
        """
        if self._options.disable_check:
            return True

        urn = Urn(remote_path)
        try:
            response = await self.execute_request(action="check", path=urn.quote())
        except RemoteResourceNotFoundError:
            return False

        return int(response.status) == 200

    async def mkdir(self, remote_path: str, *, recursive: bool = False) -> bool:
        """Make new directory on WebDAV server.

        More information you can find by link https://www.rfc-editor.org/rfc/rfc4918.html#section-9.3.

        :param remote_path: path to directory
        :param recursive: (optional) create all intermediate directories. Defaults is False.
        :return: True if request executed with code 200 or 201 and False otherwise.
        """
        directory_urn = Urn(remote_path, directory=True)
        if not await self.check(directory_urn.parent()):
            if recursive is True:
                await self.mkdir(directory_urn.parent(), recursive=True)
            else:
                raise RemoteParentNotFoundError(directory_urn.path())

        try:
            response = await self.execute_request(
                action="mkdir", path=directory_urn.quote()
            )
        except MethodNotSupportedError:
            # Yandex WebDAV returns 405 status code when directory already exists
            return True
        return response.status in (200, 201)

    async def download_iter(
        self, remote_path: str, *, timeout: ClientTimeout | None = None
    ) -> AsyncIterator[bytes]:
        """Download file from WebDAV and return content in generator.

        :param remote_path: path to file on WebDAV server.
        :param timeout: (optional) the timeout for the request.
        """
        urn = Urn(remote_path)
        if await self.is_dir(urn.path()):
            raise OptionNotValidError(name="remote_path", value=remote_path)

        if not await self.check(urn.path()):
            raise RemoteResourceNotFoundError(urn.path())

        response = await self.execute_request(
            action="download", path=urn.quote(), timeout=timeout
        )
        return _iter_content(response, self._options.chunk_size)

    async def download_from(
        self,
        buff: IO[bytes] | AsyncWriteBuffer,
        remote_path: str,
        progress: Callable[[int, int | None], None | Awaitable[None]] | None = None,
    ) -> None:
        """Download file from WebDAV and writes it in buffer.

        :param buff: buffer object for writing of downloaded file content.
        :param remote_path: path to file on WebDAV server.
        :param progress: Pass a callback function to view the file transmission progress.
                The function must take *(current, total)* as positional arguments (look at Other Parameters below for a
                detailed description) and will be called back each time a new file chunk has been successfully
                transmitted.
                `total` will be None if missing the HTTP header 'content-type' in the response from the remote.
                Example def progress_update(current, total, *args) ...
        """
        urn = Urn(remote_path)
        if await self.is_dir(urn.path()):
            raise OptionNotValidError(name="remote_path", value=remote_path)

        if not await self.check(urn.path()):
            raise RemoteResourceNotFoundError(urn.path())

        response = await self.execute_request(action="download", path=urn.quote())
        clen_str = response.headers.get("content-length")
        total = int(clen_str) if clen_str is not None else None
        current = 0

        if callable(progress):
            ret = progress(current, total)  # zero call
            if asyncio.iscoroutine(ret):
                await ret

        async for chunk in _iter_content(response, self._options.chunk_size):
            write_ret = buff.write(chunk)
            if asyncio.iscoroutine(write_ret):
                await write_ret
            current += self._options.chunk_size

            if callable(progress):
                ret = progress(current, total)
                if asyncio.iscoroutine(ret):
                    await ret

    async def download(
        self,
        remote_path: str,
        local_path: Path,
        progress: Callable[[int, int | None], Coroutine[Any, Any, None] | None]
        | None = None,
    ) -> None:
        """Download remote resource from WebDAV and save it in local path.

        More information you can find by link https://www.rfc-editor.org/rfc/rfc4918.html#section-9.4.

        :param remote_path: the path to remote resource for downloading can be file and directory.
        :param local_path: the path to save resource locally.
        :param progress: Pass a callback function to view the file transmission progress.
                The function must take *(current, total)* as positional arguments (look at Other Parameters below for a
                detailed description) and will be called back each time a new file chunk has been successfully
                transmitted. Example def progress_update(current, total, *args) ...
        """
        urn = Urn(remote_path)
        if await self.is_dir(urn.path()):
            await self.download_directory(
                local_path=local_path,
                remote_path=remote_path,
                progress=progress,
            )
        else:
            await self.download_file(
                local_path=local_path,
                remote_path=remote_path,
                progress=progress,
            )

    async def download_directory(
        self,
        remote_path: str,
        local_path: Path,
        progress: Callable[[int, int | None], Coroutine[Any, Any, None] | None]
        | None = None,
    ) -> None:
        """Download directory and downloads all nested files and directories from remote WebDAV to local.

        If there is something on local path it deletes directories and files then creates new.

        :param remote_path: the path to directory for downloading form WebDAV server.
        :param local_path: the path to local directory for saving downloaded files and directories.
        :param progress: Pass a callback function to view the file transmission progress.
                The function must take *(current, total)* as positional arguments (look at Other Parameters below for a
                detailed description) and will be called back each time a new file chunk has been successfully
                transmitted. Example def progress_update(current, total, *args) ...
        """
        urn = Urn(remote_path, directory=True)
        if not await self.is_dir(urn.path()):
            raise OptionNotValidError(name="remote_path", value=remote_path)

        if local_path.exists():
            shutil.rmtree(local_path)

        local_path.mkdir(parents=True)

        for resource_name in await self.list_files(urn.path()):
            if urn.path().endswith(resource_name):
                continue
            _remote_path = f"{urn.path()}{resource_name}"
            _local_path = Path(local_path) / resource_name
            await self.download(
                local_path=_local_path,
                remote_path=_remote_path,
                progress=progress,
            )

    async def download_file(
        self,
        remote_path: str,
        local_path: Path,
        progress: Callable[[int, int | None], Coroutine[Any, Any, None] | None]
        | None = None,
    ) -> None:
        """Download file from WebDAV server and save it locally.

        More information you can find by link https://www.rfc-editor.org/rfc/rfc4918.html#section-9.4.

        :param remote_path: the path to remote file for downloading.
        :param local_path: the path to save file locally.
        :param progress: Pass a callback function to view the file transmission progress.
                The function must take *(current, total)* as positional arguments (look at Other Parameters below for a
                detailed description) and will be called back each time a new file chunk has been successfully
                transmitted.
                `total` will be None if missing the HTTP header 'content-length' in the response from the remote.
                 Example def progress_update(current, total, *args) ...
        """
        urn = Urn(remote_path)
        if await self.is_dir(urn.path()):
            raise OptionNotValidError(name="remote_path", value=remote_path)

        if local_path.is_dir():
            raise OptionNotValidError(name="local_path", value=str(local_path))

        if not await self.check(urn.path()):
            raise RemoteResourceNotFoundError(urn.path())

        async with aiofiles.open(local_path, "wb") as local_file:
            response = await self.execute_request("download", urn.quote())
            clen_str = response.headers.get("content-length")
            total = int(clen_str) if clen_str is not None else None
            current = 0

            if callable(progress):
                ret = progress(current, total)  # zero call
                if asyncio.iscoroutine(ret):
                    await ret

            async for block in _iter_content(response, self._options.chunk_size):
                await local_file.write(block)
                current += self._options.chunk_size
                if callable(progress):
                    ret = progress(current, total)
                    if asyncio.iscoroutine(ret):
                        await ret

    async def upload_iter(
        self,
        buff: str | IO[bytes] | AsyncIterator[bytes] | AsyncWriteBuffer,
        remote_path: str,
        *,
        timeout: ClientTimeout | None = None,
        content_length: int | None = None,
    ) -> None:
        """Upload file from buffer to remote path on WebDAV server.

        More information you can find by link https://www.rfc-editor.org/rfc/rfc4918.html#section-9.7.

        :param buff: the buffer with content for file.
        :param str remote_path: the path to save file remotely on WebDAV server.
        :param timeout: (optional) the timeout for the request.
        :param content_length: (optional) the length of content in buffer.
        """
        urn = Urn(remote_path)
        if urn.is_dir():
            raise OptionNotValidError(name="remote_path", value=remote_path)

        if not await self.check(urn.parent()):
            raise RemoteParentNotFoundError(urn.path())

        headers = []
        if content_length is not None:
            headers.append(f"Content-Length: {content_length}")

        await self.execute_request(
            action="upload",
            path=urn.quote(),
            data=buff,
            timeout=timeout,
            headers_ext=headers,
        )

    async def upload(
        self,
        remote_path: str,
        local_path: Path,
        progress: Callable[[int, int | None], Coroutine[Any, Any, None] | None]
        | None = None,
    ) -> None:
        """Upload resource to remote path on WebDAV server.

        In case resource is directory it will upload all nested files and directories.
        More information you can find by link https://www.rfc-editor.org/rfc/rfc4918.html#section-9.7.

        :param remote_path: the path for uploading resources on WebDAV server. Can be file and directory.
        :param local_path: the path to local resource for uploading.
        :param progress: Pass a callback function to view the file transmission progress.
                The function must take *(current, total)* as positional arguments (look at Other Parameters below for a
                detailed description) and will be called back each time a new file chunk has been successfully
                transmitted. Example def progress_update(current, total, *args) ...
        """
        if local_path.is_dir():
            await self.upload_directory(
                local_path=local_path,
                remote_path=remote_path,
                progress=progress,
            )
        else:
            await self.upload_file(
                local_path=local_path,
                remote_path=remote_path,
                progress=progress,
            )

    async def upload_directory(
        self,
        remote_path: str,
        local_path: Path,
        progress: Callable[[int, int | None], Coroutine[Any, Any, None] | None]
        | None = None,
    ) -> None:
        """Upload directory to remote path on WebDAV server.

        In case directory is exist on remote server it will delete it and then upload directory with nested files and
        directories.

        :param remote_path: the path to directory for uploading on WebDAV server.
        :param local_path: the path to local directory for uploading.
        :param progress: Pass a callback function to view the file transmission progress.
                The function must take *(current, total)* as positional arguments (look at Other Parameters below for a
                detailed description) and will be called back each time a new file chunk has been successfully
                transmitted. Example def progress_update(current, total, *args) ...
        """
        urn = Urn(remote_path, directory=True)
        if not urn.is_dir():
            raise OptionNotValidError(name="remote_path", value=remote_path)

        if not local_path.is_dir():
            raise OptionNotValidError(name="local_path", value=str(local_path))

        if not local_path.exists():
            raise LocalResourceNotFoundError(str(local_path))

        await self.mkdir(remote_path)

        for resource_name in local_path.iterdir():
            _remote_path = f"{urn.path()}{resource_name}".replace("\\", "")
            _local_path = local_path / resource_name
            await self.upload(
                local_path=_local_path,
                remote_path=_remote_path,
                progress=progress,
            )

    async def upload_file(
        self,
        remote_path: str,
        local_path: Path,
        progress: Callable[[int, int | None], Coroutine[Any, Any, None] | None]
        | None = None,
        *,
        force: bool = False,
    ) -> None:
        """Upload file to remote path on WebDAV server. File should be 2Gb or less.

        More information you can find by link https://www.rfc-editor.org/rfc/rfc4918.html#section-9.7.

        :param remote_path: the path to uploading file on WebDAV server.
        :param local_path: the path to local file for uploading.
        :param progress: Pass a callback function to view the file transmission progress.
                The function must take *(current, total)* as positional arguments (look at Other Parameters below for a
                detailed description) and will be called back each time a new file chunk has been successfully
                transmitted. Example def progress_update(current, total, *args) ...
        :param force:  if the directory isn't there it will creat the directory.
        """
        if not local_path.exists():
            raise LocalResourceNotFoundError(str(local_path))

        urn = Urn(remote_path)
        if urn.is_dir():
            raise OptionNotValidError(name="remote_path", value=remote_path)

        if local_path.is_dir():
            raise OptionNotValidError(name="local_path", value=str(local_path))

        if not await self.check(urn.parent()):
            if force is True:
                await self.mkdir(urn.parent(), recursive=True)
            else:
                raise RemoteParentNotFoundError(urn.path())

        async with aiofiles.open(local_path, "rb") as local_file:
            total = local_path.stat().st_size

            async def read_in_chunks(
                file_object: aiofiles.threadpool.binary.AsyncBufferedIOBase,
            ) -> AsyncIterable[bytes]:
                if callable(progress):
                    ret = progress(0, total)
                    if asyncio.iscoroutine(ret):
                        await ret
                current = 0

                while current < total:
                    data = await file_object.read(self._options.chunk_size)
                    if callable(progress):
                        ret = progress(current, total)  # call to progress function
                        if asyncio.iscoroutine(ret):
                            await ret
                    current += len(data)
                    if not data:
                        break
                    yield data

            if callable(progress):
                await self.execute_request(
                    action="upload", path=urn.quote(), data=read_in_chunks(local_file)
                )
            else:
                await self.execute_request(
                    action="upload", path=urn.quote(), data=local_file
                )

    async def copy(
        self, remote_path_from: str, remote_path_to: str, depth: int = 1
    ) -> None:
        """Copy resource from one place to another on WebDAV server.

        More information you can find by link https://www.rfc-editor.org/rfc/rfc4918.html#section-9.8.

        :param remote_path_from: the path to resource which will be copied,
        :param remote_path_to: the path where resource will be copied.
        :param depth: folder depth to copy
        """
        urn_from = Urn(remote_path_from)
        if not await self.check(urn_from.path()):
            raise RemoteResourceNotFoundError(urn_from.path())

        urn_to = Urn(remote_path_to)
        if not await self.check(urn_to.parent()):
            raise RemoteParentNotFoundError(urn_to.path())

        headers = [f"Destination: {self.get_url(urn_to.quote())}"]
        if await self.is_dir(urn_from.path()):
            headers.append(f"Depth: {depth}")
        await self.execute_request(
            action="copy", path=urn_from.quote(), headers_ext=headers
        )

    async def move(
        self, remote_path_from: str, remote_path_to: str, *, overwrite: bool = False
    ) -> None:
        """Move resource from one place to another on WebDAV server.

        More information you can find by link https://www.rfc-editor.org/rfc/rfc4918.html#section-9.9.

        :param remote_path_from: the path to resource which will be moved,
        :param remote_path_to: the path where resource will be moved.
        :param overwrite: (optional) the flag, overwrite file if it exists. Defaults is False
        """
        urn_from = Urn(remote_path_from)
        if not await self.check(urn_from.path()):
            raise RemoteResourceNotFoundError(urn_from.path())

        urn_to = Urn(remote_path_to)
        if not await self.check(urn_to.parent()):
            raise RemoteParentNotFoundError(urn_to.path())

        header_destination = f"Destination: {self.get_url(urn_to.quote())}"
        header_overwrite = f"Overwrite: {'T' if overwrite else 'F'}"
        await self.execute_request(
            action="move",
            path=urn_from.quote(),
            headers_ext=[header_destination, header_overwrite],
        )

    async def clean(self, remote_path: str) -> None:
        """Clean (delete) a remote resource on WebDAV server.

        The name of method is not changed for back compatibility with original library.

        More information you can find by link https://www.rfc-editor.org/rfc/rfc4918.html#section-9.6.

        :param remote_path: the remote resource whisch will be deleted.
        """
        urn = Urn(remote_path)
        await self.execute_request(action="clean", path=urn.quote())

    async def info(self, remote_path: str) -> dict[str, str]:
        """Get information about resource on WebDAV.

        More information you can find by link https://www.rfc-editor.org/rfc/rfc4918.html#section-9.1.

        :param str remote_path: the path to remote resource.
        :return: a dictionary of information attributes and them values with following keys:
                 `created`: date of resource creation,
                 `name`: name of resource,
                 `size`: size of resource,
                 `modified`: date of resource modification,
                 `etag`: etag of resource,
                 `content_type`: content type of resource.
        """
        urn = Urn(remote_path)
        await self._check_remote_resource(remote_path, urn)

        response = await self.execute_request(action="info", path=urn.quote())
        path = self.get_full_path(urn)
        return WebDavXmlUtils.parse_info_response(
            content=await response.read(), path=path, hostname=self._url
        )

    async def _check_remote_resource(self, remote_path: str, urn: Urn) -> None:
        if not await self.check(urn.path()) and not await self.check(
            Urn(remote_path, directory=True).path()
        ):
            raise RemoteResourceNotFoundError(remote_path)

    async def is_dir(self, remote_path: str) -> bool:
        """Check is the remote resource directory.

        More information you can find by link https://www.rfc-editor.org/rfc/rfc4918.html#section-9.1.

        :param remote_path: the path to remote resource.
        :return: True in case the remote resource is directory and False otherwise.
        """
        urn = Urn(remote_path)
        await self._check_remote_resource(remote_path, urn)

        response = await self.execute_request(
            action="info", path=urn.quote(), headers_ext=["Depth: 0"]
        )
        path = self.get_full_path(urn)
        return WebDavXmlUtils.parse_is_dir_response(
            content=await response.read(), path=path, hostname=self._url
        )

    async def get_property(
        self, remote_path: str, requested_property: PropertyRequest
    ) -> Property | None:
        """Get metadata property of remote resource on WebDAV server.

        More information you can find by link https://www.rfc-editor.org/rfc/rfc4918.html#section-9.1.

        :param remote_path: the path to remote resource.
        :param requested_property: the property attribute as dictionary with following keys:
                       `namespace`: (optional) the namespace for XML property which will be set,
                       `name`: the name of property which will be set.
        :return: the value of property or None if property is not found.
        """
        result = await self.get_properties(remote_path, [requested_property])
        return result[0] if result and result[0] else None

    async def get_properties(
        self, remote_path: str, requested_properties: list[PropertyRequest]
    ) -> list[Property]:
        """Get metadata properties of remote resource on WebDAV server."""
        urn = Urn(remote_path)
        if not await self.check(urn.path()):
            raise RemoteResourceNotFoundError(urn.path())

        data = WebDavXmlUtils.create_get_property_batch_request_content(
            requested_properties
        )
        response = await self.execute_request(
            action="get_property", path=urn.quote(), data=data
        )
        return WebDavXmlUtils.parse_get_properties_response(
            await response.read(), requested_properties
        )

    async def set_property(self, remote_path: str, prop: Property) -> None:
        """Set metadata property of remote resource on WebDAV server.

        More information you can find by link https://www.rfc-editor.org/rfc/rfc4918.html#section-9.2.

        :param remote_path: the path to remote resource.
        :param prop: the property attribute as dictionary with following keys:
                       `namespace`: (optional) the namespace for XML property which will be set,
                       `name`: the name of property which will be set,
                       `value`: (optional) the value of property which will be set. Defaults is empty string.
        """
        await self.set_property_batch(remote_path=remote_path, properties=[prop])

    async def set_property_batch(
        self, remote_path: str, properties: list[Property]
    ) -> None:
        """Set batch metadata properties of remote resource on WebDAV server in batch.

        More information you can find by link https://www.rfc-editor.org/rfc/rfc4918.html#section-9.2.

        :param remote_path: the path to remote resource.
        :param properties: the property attributes as list of dictionaries with following keys:
                       `namespace`: (optional) the namespace for XML property which will be set,
                       `name`: the name of property which will be set,
                       `value`: (optional) the value of property which will be set. Defaults is empty string.
        """
        urn = Urn(remote_path)
        if not await self.check(urn.path()):
            raise RemoteResourceNotFoundError(urn.path())

        data = WebDavXmlUtils.create_set_property_batch_request_content(properties)
        await self.execute_request(action="set_property", path=urn.quote(), data=data)

    async def lock(
        self, remote_path: str = DEFAULT_ROOT, timeout: int = 0
    ) -> "LockClient":
        """Create a lock on the given path and returns a LockClient that handles the lock.

        To ensure the lock is released this should be called using with `with client.lock("path") as c:`.
        More information at https://www.rfc-editor.org/rfc/rfc4918.html#section-9.10.

        :param remote_path: the path to remote resource to lock.
        :param timeout: the timeout for the lock (default infinite).
        :return: LockClient that wraps the Client and handle the lock
        """
        headers_ext = None
        if timeout > 0:
            headers_ext = [f"Timeout: Second-{timeout}"]

        response = await self.execute_request(
            action="lock",
            path=Urn(remote_path).quote(),
            headers_ext=headers_ext,
            data="""<D:lockinfo xmlns:D='DAV:'>
                <D:lockscope>
                    <D:exclusive/>
                </D:lockscope>
                    <D:locktype>
                    <D:write/>
                </D:locktype>
            </D:lockinfo>""",
        )

        return LockClient(
            url=self._url,
            username=self._username,
            password=self._password,
            lock_path=Urn(remote_path).quote(),
            lock_token=response.headers["Lock-Token"],
            options=self._options,
        )

    def resource(self, remote_path: str) -> "Resource":
        """Return a resource object for the given path.

        :param remote_path: the path to remote resource.
        :return: Resource object for the given path.
        """
        urn = Urn(remote_path)
        return Resource(self, urn)

    async def push(self, remote_directory: str, local_directory: Path) -> bool:
        """Pushe local directory to remote directory on WebDAV server.

        :param remote_directory: the path to remote directory for pushing.
        :param local_directory: the path to local directory for pushing.
        :return: True if local directory is more recent than remote directory, False otherwise.
        """

        def prune(src: list[str], exp: str) -> list[str]:
            return [sub(exp, "", item) for item in src]

        updated = False
        urn = Urn(remote_directory, directory=True)
        await self._validate_remote_directory(urn)
        self._validate_local_directory(local_directory)

        paths = await self.list_files(urn.path())
        expression = f"^{urn.path()}"
        remote_resource_names = prune(paths, expression)

        for local_resource_name in local_directory.iterdir():
            local_path = local_directory / local_resource_name
            remote_path = f"{urn.path()}{local_resource_name}"

            if local_path.is_dir():
                if not await self.check(remote_path=remote_path):
                    await self.mkdir(remote_path=remote_path)
                result = await self.push(
                    remote_directory=remote_path, local_directory=local_path
                )
                updated = updated or result
            else:
                if (
                    local_resource_name in remote_resource_names
                    and not self.is_local_more_recent(local_path, remote_path)
                ):
                    continue
                await self.upload_file(remote_path=remote_path, local_path=local_path)
                updated = True
        return updated

    async def pull(self, remote_directory: str, local_directory: Path) -> bool:
        """Pull remote directory to local directory.

        :param remote_directory: the path to remote directory for pulling.
        :param local_directory: the path to local directory for pulling.
        :return: True if remote directory is more recent than local directory, False otherwise.
        """

        def prune(src: list[str], exp: str) -> list[str]:
            return [sub(exp, "", item) for item in src]

        updated = False
        urn = Urn(remote_directory, directory=True)
        await self._validate_remote_directory(urn)
        self._validate_local_directory(local_directory)

        local_resource_names = [item.name for item in local_directory.iterdir()]

        paths = await self.list_files(urn.path())
        expression = f"^{remote_directory}"
        remote_resource_names = prune(paths, expression)

        for remote_resource_name in remote_resource_names:
            if urn.path().endswith(remote_resource_name):
                continue
            local_path = local_directory / remote_resource_name
            remote_path = f"{urn.path()}{remote_resource_name}"
            remote_urn = Urn(remote_path)

            if remote_urn.path().endswith("/"):
                if not local_path.exists():
                    updated = True
                    local_path.mkdir()
                result = await self.pull(
                    remote_directory=remote_path, local_directory=local_path
                )
                updated = updated or result
            else:
                if (
                    remote_resource_name in local_resource_names
                    and self.is_local_more_recent(local_path, remote_path)
                ):
                    continue

                await self.download_file(remote_path=remote_path, local_path=local_path)
                updated = True
        return updated

    async def is_local_more_recent(
        self, local_path: Path, remote_path: str
    ) -> bool | None:
        """Tell if local resource is more recent that the remote on if possible.

        :param str local_path: the path to local resource.
        :param str remote_path: the path to remote resource.

        :return: True if local resource is more recent, False if the remote one is
                 None if comparison is not possible
        """
        try:
            remote_info = await self.info(remote_path)
            remote_last_mod_date = str(remote_info["modified"])
            remote_last_mod_date_converted = dateutil_parse(remote_last_mod_date)
            remote_last_mod_date_unix_ts = int(
                remote_last_mod_date_converted.timestamp()
            )
            local_last_mod_date_unix_ts = int(local_path.stat().st_mtime)
        except (ValueError, RuntimeWarning, KeyError):
            _LOGGER.exception(
                "Error while parsing dates or getting last modified informationruff",
            )

            # If there is problem when parsing dates, or cannot get
            # last modified information, return None
            return None

        return local_last_mod_date_unix_ts > remote_last_mod_date_unix_ts

    async def sync(self, remote_directory: str, local_directory: Path) -> None:
        """Synchronize local and remote directories.

        :param remote_directory: the path to remote directory for synchronization.
        :param local_directory: the path to local directory for synchronization.
        """
        await self.pull(
            remote_directory=remote_directory, local_directory=local_directory
        )
        await self.push(
            remote_directory=remote_directory, local_directory=local_directory
        )

    async def publish(self, path: str) -> None:
        """Publish resource on WebDAV server.

        :param path: the path to resource for publishing.
        """
        await self.execute_request("publish", path)

    async def unpublish(self, path: str) -> None:
        """Unpublish resource on WebDAV server.

        :param path: the path to resource for unpublishing.
        """
        await self.execute_request("unpublish", path)

    async def _validate_remote_directory(self, urn: Urn) -> None:
        """Validate remote directory."""
        if not await self.is_dir(urn.path()):
            raise OptionNotValidError(name="remote_path", value=urn.path())

    @staticmethod
    def _validate_local_directory(local_directory: Path) -> None:
        """Validate local directory."""
        if not local_directory.is_dir():
            raise OptionNotValidError(name="local_path", value=str(local_directory))

        if not local_directory.exists():
            raise LocalResourceNotFoundError(str(local_directory))

    async def close(self) -> None:
        """Close the connection to WebDAV server."""
        if self._close_session:
            await self._session.close()

    async def __aenter__(self) -> Self:
        """Async enter."""
        return self

    async def __aexit__(self, *_exc_info: object) -> None:
        """Async exit."""
        await self.close()


class Resource:
    """Representation of resource on WebDAV server."""

    def __init__(self, client: Client, urn: Urn) -> None:
        """Representation of resource on WebDAV server."""
        self.client = client
        self.urn = urn

    def __str__(self) -> str:
        """Return string representation of the resource."""
        return f"resource {self.urn.path()}"

    async def is_dir(self) -> bool:
        """Check is the resource directory."""
        return await self.client.is_dir(self.urn.path())

    async def rename(self, new_name: str) -> None:
        """Rename the resource."""
        old_path = self.urn.path()
        parent_path = self.urn.parent()
        new_name = Urn(new_name).filename()
        new_path = f"{parent_path}{new_name}"

        await self.client.move(remote_path_from=old_path, remote_path_to=new_path)
        self.urn = Urn(new_path)

    async def move(self, remote_path: str) -> None:
        """Move the resource to another place."""
        new_urn = Urn(remote_path)
        await self.client.move(
            remote_path_from=self.urn.path(), remote_path_to=new_urn.path()
        )
        self.urn = new_urn

    async def copy(self, remote_path: str) -> "Resource":
        """Copy the resource to another place."""
        urn = Urn(remote_path)
        await self.client.copy(
            remote_path_from=self.urn.path(), remote_path_to=remote_path
        )
        return Resource(self.client, urn)

    async def info(self, params: dict[str, str] | None = None) -> dict[str, str]:
        """Get information about resource on WebDAV."""
        info = await self.client.info(self.urn.path())
        if not params:
            return info

        return {key: value for (key, value) in info.items() if key in params}

    async def clean(self) -> None:
        """Clean (delete) the resource."""
        await self.client.clean(self.urn.path())

    async def check(self) -> bool:
        """Check is the resource exists."""
        return await self.client.check(self.urn.path())

    async def read_from(self, buff: IO[bytes] | AsyncWriteBuffer) -> None:
        """Read the resource to buffer."""
        await self.client.upload_iter(buff=buff, remote_path=self.urn.path())

    async def read(self, local_path: Path) -> None:
        """Read the resource to local path."""
        await self.client.upload(local_path=local_path, remote_path=self.urn.path())

    async def write_to(self, buff: IO[bytes] | AsyncWriteBuffer) -> None:
        """Write the buffer to the resource."""
        await self.client.download_from(buff=buff, remote_path=self.urn.path())

    async def write(self, local_path: Path) -> None:
        """Write the local path to the resource."""
        await self.client.download(local_path=local_path, remote_path=self.urn.path())

    async def publish(self) -> None:
        """Publish the resource."""
        await self.client.publish(self.urn.path())

    async def unpublish(self) -> None:
        """Unpublish the resource."""
        await self.client.unpublish(self.urn.path())

    async def get_property(
        self, requested_property: PropertyRequest
    ) -> Property | None:
        """Get metadata property of the resource."""
        return await self.client.get_property(self.urn.path(), requested_property)

    async def set_property(self, name: str, value: str, namespace: str = "") -> None:
        """Set metadata property of the resource."""
        await self.client.set_property(
            self.urn.path(), Property(name=name, value=value, namespace=namespace)
        )


class LockClient(Client):
    """Client for handling locks on WebDAV server."""

    def __init__(
        self,
        *,
        url: str,
        username: str,
        password: str,
        lock_path: str,
        lock_token: str,
        options: ClientOptions | None = None,
    ) -> None:
        """Client for handling locks on WebDAV server."""
        super().__init__(url=url, username=username, password=password, options=options)

        self.__lock_path = lock_path
        self.__lock_token = lock_token

    def get_headers(
        self, action: str, headers_ext: list[str] | None = None
    ) -> dict[str, str]:
        """Get headers for request to WebDAV server."""
        headers = super().get_headers(action, headers_ext)
        headers["Lock-Token"] = self.__lock_token
        headers["If"] = f"({self.__lock_token})"
        return headers

    async def __aenter__(self) -> Self:
        """Async enter."""
        await self.execute_request(action="lock", path=self.__lock_path)
        return await super().__aenter__()

    async def __aexit__(self, *_exc_info: object) -> None:
        """Async exit."""
        await super().__aexit__()
        await self.execute_request(action="unlock", path=self.__lock_path)
