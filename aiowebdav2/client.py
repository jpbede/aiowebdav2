"""WebDAV client implementation."""
import asyncio
from collections.abc import AsyncIterable, Awaitable, Callable
import functools
from datetime import datetime
from io import BytesIO
import logging
import os
from re import sub
import shutil
from typing import IO
from urllib.parse import unquote, urlparse, urlsplit

import aiofiles
import aiohttp
from aiowebdav2.connection import WebDAVSettings
from aiowebdav2.exceptions import (
    ConnectionException,
    LocalResourceNotFound,
    MethodNotSupported,
    NoConnection,
    NotEnoughSpace,
    OptionNotValid,
    RemoteParentNotFound,
    RemoteResourceNotFound,
    ResourceLocked,
    ResponseErrorCode,
)
from aiowebdav2.typing import AsyncWriteBuffer
from aiowebdav2.urn import Urn
from lxml import etree

log = logging.getLogger(__name__)


def listdir(directory):
    """Returns list of nested files and directories for local directory by path

    :param directory: absolute or relative path to local directory
    :return: list nested of file or directory names
    """
    file_names = list()
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        if os.path.isdir(file_path):
            filename = f"{filename}{os.path.sep}"
        file_names.append(filename)
    return file_names


def get_options(option_type: type[WebDAVSettings], from_options) -> dict:
    """Extract options for specified option type from all options

    :param option_type: the object of specified type of options
    :param from_options: all options dictionary
    :return: the dictionary of options for specified type, each option can be filled by value from all options
             dictionary or blank in case the option for specified type is not exist in all options dictionary
    """
    _options = dict()

    for key in option_type.keys:
        key_with_prefix = f"{option_type.prefix}{key}"
        if key not in from_options and key_with_prefix not in from_options:
            _options[key] = ""
        elif key in from_options:
            _options[key] = from_options.get(key)
        else:
            _options[key] = from_options.get(key_with_prefix)

    return _options


def wrap_connection_error(fn):
    """Decorator to handle aiohttp errors."""

    @functools.wraps(fn)
    async def _wrapper(self, *args, **kw):
        log.debug("Requesting %s(%s, %s)", fn, args, kw)
        try:
            res = fn(self, *args, **kw)
            if asyncio.iscoroutine(res):
                res = await res
        except aiohttp.ClientConnectionError:
            raise NoConnection(self.webdav.hostname)
        except aiohttp.ClientResponseError as re:
            raise ConnectionException(re)
        else:
            return res

    return _wrapper


async def iter_content(response: aiohttp.ClientResponse, chunk_size) -> AsyncIterable:
    """Async generator to iterate over response content by chunks."""
    while chunk := await response.content.read(chunk_size):
        yield chunk


class Client:
    """The client for WebDAV servers provides an ability to control files on remote WebDAV server."""

    # path to root directory of WebDAV
    root = "/"

    # controls whether to verify the server's TLS certificate or not
    verify = True

    # HTTP headers for different actions
    default_http_header = {
        "list": ["Accept: */*", "Depth: 1"],
        "free": ["Accept: */*", "Depth: 0", "Content-Type: text/xml"],
        "copy": ["Accept: */*"],
        "move": ["Accept: */*"],
        "mkdir": ["Accept: */*", "Connection: Keep-Alive"],
        "clean": ["Accept: */*", "Connection: Keep-Alive"],
        "check": ["Accept: */*"],
        "info": ["Accept: */*", "Depth: 1"],
        "get_property": [
            "Accept: */*",
            "Depth: 1",
            "Content-Type: application/x-www-form-urlencoded",
        ],
        "set_property": [
            "Accept: */*",
            "Depth: 1",
            "Content-Type: application/x-www-form-urlencoded",
        ],
    }

    # mapping of actions to WebDAV methods
    default_requests = {
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

    meta_xmlns = {
        "https://webdav.yandex.ru": "urn:yandex:disk:meta",
    }

    def __init__(self, options):
        """Constructor of WebDAV client

        :param options: the dictionary of connection options to WebDAV.
            WebDev settings:
            `webdav_hostname`: url for WebDAV server should contain protocol and ip address or domain name.
                               Example: `https://webdav.server.com`.
            `webdav_login`: (optional) Login name for WebDAV server. Can be empty when using token auth.
            `webdav_password`: (optional) Password for WebDAV server. Can be empty when using token auth.
            `webdav_token': (optional) Authentication token for WebDAV server. Can be empty when using login/password auth.
            `webdav_root`: (optional) Root directory of WebDAV server. Default is `/`.
            `webdav_cert_path`: (optional) Path to client certificate.
            `webdav_key_path`: (optional) Path to private key of the client certificate.
            `webdav_recv_speed`: (optional) Rate limit of data download speed in Bytes per second.
                                 Defaults to unlimited speed.
            `webdav_send_speed`: (optional) Rate limit of data upload speed in Bytes per second.
                                 Defaults to unlimited speed.
            `webdav_timeout`: (optional) Timeout in seconds used in HTTP connection managed by requests. Defaults to 30 seconds.
            `webdav_verbose`: (optional) Set verbose mode on/off. By default verbose mode is off.

        """
        self.session = aiohttp.ClientSession()
        self.http_header = self.default_http_header.copy()
        self.requests = self.default_requests.copy()
        webdav_options = get_options(option_type=WebDAVSettings, from_options=options)

        self.webdav = WebDAVSettings(webdav_options)
        self.requests.update(self.webdav.override_methods)
        self.default_options = {}
        self.timeout = self.webdav.timeout
        self.chunk_size = 65536

    def get_headers(self, action: str, headers_ext: list = None) -> dict:
        """Returns HTTP headers of specified WebDAV actions.

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
            headers = list()

        if headers_ext:
            headers.extend(headers_ext)

        if self.webdav.token:
            webdav_token = f"Authorization: Bearer {self.webdav.token}"
            headers.append(webdav_token)
        return dict([map(lambda s: s.strip(), i.split(":", 1)) for i in headers])

    def get_url(self, path):
        """Generates url by uri path.

        :param path: uri path.
        :return: the url string.
        """
        url = {"hostname": self.webdav.hostname, "root": self.webdav.root, "path": path}
        return "{hostname}{root}{path}".format(**url)

    def get_full_path(self, urn: str) -> str:
        """Generates full path to remote resource exclude hostname.

        :param urn: the URN to resource.
        :return: full path to resource with root path.
        """
        return f"{unquote(self.webdav.root)}{urn.path()}"

    async def execute_request(
        self, action, path, data=None, headers_ext=None
    ) -> aiohttp.ClientResponse:
        """Generate request to WebDAV server for specified action and path and execute it.

        :param action: the action for WebDAV server which should be executed.
        :param path: the path to resource for action
        :param data: (optional) Dictionary or list of tuples ``[(key, value)]`` (will be form-encoded), bytes,
                     or file-like object to send in the body of the :class:`Request`.
        :param headers_ext: (optional) the addition headers list witch should be added to basic HTTP headers for
                            the specified action.
        :return: HTTP response of request.
        """
        response = await self.session.request(
            method=self.requests[action],
            url=self.get_url(path),
            auth=aiohttp.BasicAuth(self.webdav.login, self.webdav.password)
            if (not self.webdav.token and not self.session.auth)
            and (self.webdav.login and self.webdav.password)
            else None,
            headers=self.get_headers(action, headers_ext),
            timeout=self.timeout,
            ssl=self.webdav.ssl,
            data=data,
            verify_ssl=self.verify,
            proxy=self.webdav.proxy,
            proxy_auth=self.webdav.proxy_auth,
        )
        if response.status == 507:
            raise NotEnoughSpace()
        if response.status == 404:
            raise RemoteResourceNotFound(path=path)
        if response.status == 423:
            raise ResourceLocked(path=path)
        if response.status == 405:
            raise MethodNotSupported(name=action, server=self.webdav.hostname)
        if response.status >= 400:
            raise ResponseErrorCode(
                url=self.get_url(path),
                code=response.status,
                message=await response.read(),
            )
        return response

    def valid(self):
        """Validates of WebDAV settings.

        :return: True in case settings are valid and False otherwise.
        """
        return True if self.webdav.valid() else False

    @wrap_connection_error
    async def list(self, remote_path=root, get_info=False, recursive=False):
        """Returns list of nested files and directories for remote WebDAV directory by path.
        More information you can find by link http://webdav.org/specs/rfc4918.html#METHOD_PROPFIND

        :param remote_path: path to remote directory.
        :param get_info: path and element info to remote directory, like cmd 'ls -l'.
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
        if recursive == True:
            headers = ["Depth:infinity"]
        directory_urn = Urn(remote_path, directory=True)
        if directory_urn.path() != Client.root and not await self.check(
            directory_urn.path()
        ):
            raise RemoteResourceNotFound(directory_urn.path())

        path = Urn.normalize_path(self.get_full_path(directory_urn))
        response = await self.execute_request(
            action="list", path=directory_urn.quote(), headers_ext=headers
        )
        if get_info:
            subfiles = WebDavXmlUtils.parse_get_list_info_response(
                await response.read()
            )
            return [
                subfile
                for subfile in subfiles
                if Urn.compare_path(path, subfile.get("path")) is False
            ]

        urns = WebDavXmlUtils.parse_get_list_response(await response.read())

        return [
            urn.filename()
            for urn in urns
            if Urn.compare_path(path, urn.path()) is False
        ]

    @wrap_connection_error
    async def free(self):
        """Returns an amount of free space on remote WebDAV server.
        More information you can find by link http://webdav.org/specs/rfc4918.html#METHOD_PROPFIND

        :return: an amount of free space in bytes.
        """
        data = WebDavXmlUtils.create_free_space_request_content()
        response = await self.execute_request(action="free", path="", data=data)
        return WebDavXmlUtils.parse_free_space_response(
            await response.read(), self.webdav.hostname
        )

    @wrap_connection_error
    async def check(self, remote_path=root):
        """Checks an existence of remote resource on WebDAV server by remote path.
        More information you can find by link http://webdav.org/specs/rfc4918.html#rfc.section.9.4

        :param remote_path: (optional) path to resource on WebDAV server. Defaults is root directory of WebDAV.
        :return: True if resource is exist or False otherwise
        """
        if self.webdav.disable_check:
            return True

        urn = Urn(remote_path)
        try:
            response = await self.execute_request(action="check", path=urn.quote())
        except RemoteResourceNotFound:
            return False

        if int(response.status) == 200:
            return True
        return False

    @wrap_connection_error
    async def mkdir(self, remote_path, recursive=False):
        """Makes new directory on WebDAV server.
        More information you can find by link http://webdav.org/specs/rfc4918.html#METHOD_MKCOL

        :param remote_path: path to directory
        :return: True if request executed with code 200 or 201 and False otherwise.

        """
        directory_urn = Urn(remote_path, directory=True)
        if not await self.check(directory_urn.parent()):
            if recursive == True:
                await self.mkdir(directory_urn.parent(), recursive=True)
            else:
                raise RemoteParentNotFound(directory_urn.path())

        try:
            print(f"Making Directory {remote_path}")
            response = await self.execute_request(
                action="mkdir", path=directory_urn.quote()
            )
            print(f"Made Directory {remote_path}")
        except MethodNotSupported:
            # Yandex WebDAV returns 405 status code when directory already exists
            return True
        return response.status in (200, 201)

    @wrap_connection_error
    async def download_iter(self, remote_path) -> AsyncIterable:
        """Downloads file from WebDAV and return content in generator

        :param remote_path: path to file on WebDAV server.
        """
        urn = Urn(remote_path)
        if await self.is_dir(urn.path()):
            raise OptionNotValid(name="remote_path", value=remote_path)

        if not await self.check(urn.path()):
            raise RemoteResourceNotFound(urn.path())

        response = await self.execute_request(action="download", path=urn.quote())
        return iter_content(response, self.chunk_size)

    @wrap_connection_error
    async def download_from(
        self,
        buff: IO | AsyncWriteBuffer,
        remote_path: str,
        progress: Callable[..., None | Awaitable[None]] = None,
        progress_args=(),
    ) -> None:
        """Downloads file from WebDAV and writes it in buffer.

        :param buff: buffer object for writing of downloaded file content.
        :param remote_path: path to file on WebDAV server.
        :param progress: Pass a callback function to view the file transmission progress.
                The function must take *(current, total)* as positional arguments (look at Other Parameters below for a
                detailed description) and will be called back each time a new file chunk has been successfully
                transmitted.
                `total` will be None if missing the HTTP header 'content-type' in the response from the remote.
                Example def progress_update(current, total, *args) ...
        :param progress_args: A tuple with extra custom arguments for the progress callback function.
                You can pass anything you need to be available in the progress callback scope; for example, a Message
                object or a Client instance in order to edit the message with the updated progress status.
        """
        urn = Urn(remote_path)
        if await self.is_dir(urn.path()):
            raise OptionNotValid(name="remote_path", value=remote_path)

        if not await self.check(urn.path()):
            raise RemoteResourceNotFound(urn.path())

        response = await self.execute_request(action="download", path=urn.quote())
        clen_str = response.headers.get("content-length")
        total = int(clen_str) if clen_str is not None else None
        current = 0

        if callable(progress):
            ret = progress(current, total, *progress_args)  # zero call
            if asyncio.iscoroutine(ret):
                await ret

        async for chunk in iter_content(response, self.chunk_size):
            ret = buff.write(chunk)
            if asyncio.iscoroutine(ret):
                await ret
            current += self.chunk_size
            if callable(progress):
                ret = progress(current, total, *progress_args)
                if asyncio.iscoroutine(ret):
                    await ret

    async def download(self, remote_path, local_path, progress=None, progress_args=()):
        """Downloads remote resource from WebDAV and save it in local path.
        More information you can find by link http://webdav.org/specs/rfc4918.html#rfc.section.9.4

        :param remote_path: the path to remote resource for downloading can be file and directory.
        :param local_path: the path to save resource locally.
        :param progress: Pass a callback function to view the file transmission progress.
                The function must take *(current, total)* as positional arguments (look at Other Parameters below for a
                detailed description) and will be called back each time a new file chunk has been successfully
                transmitted. Example def progress_update(current, total, *args) ...
        :param progress_args: A tuple with extra custom arguments for the progress callback function.
                You can pass anything you need to be available in the progress callback scope; for example, a Message
                object or a Client instance in order to edit the message with the updated progress status.
        """
        urn = Urn(remote_path)
        if await self.is_dir(urn.path()):
            await self.download_directory(
                local_path=local_path,
                remote_path=remote_path,
                progress=progress,
                progress_args=progress_args,
            )
        else:
            await self.download_file(
                local_path=local_path,
                remote_path=remote_path,
                progress=progress,
                progress_args=progress_args,
            )

    async def download_directory(
        self, remote_path, local_path, progress=None, progress_args=()
    ):
        """Downloads directory and downloads all nested files and directories from remote WebDAV to local.
        If there is something on local path it deletes directories and files then creates new.

        :param remote_path: the path to directory for downloading form WebDAV server.
        :param local_path: the path to local directory for saving downloaded files and directories.
        :param progress: Pass a callback function to view the file transmission progress.
                The function must take *(current, total)* as positional arguments (look at Other Parameters below for a
                detailed description) and will be called back each time a new file chunk has been successfully
                transmitted. Example def progress_update(current, total, *args) ...
        :param progress_args: A tuple with extra custom arguments for the progress callback function.
                You can pass anything you need to be available in the progress callback scope; for example, a Message
                object or a Client instance in order to edit the message with the updated progress status.
        """
        urn = Urn(remote_path, directory=True)
        if not await self.is_dir(urn.path()):
            raise OptionNotValid(name="remote_path", value=remote_path)

        if os.path.exists(local_path):
            shutil.rmtree(local_path)

        os.makedirs(local_path)

        for resource_name in await self.list(urn.path()):
            if urn.path().endswith(resource_name):
                continue
            _remote_path = f"{urn.path()}{resource_name}"
            _local_path = os.path.join(local_path, resource_name)
            await self.download(
                local_path=_local_path,
                remote_path=_remote_path,
                progress=progress,
                progress_args=progress_args,
            )

    @wrap_connection_error
    async def download_file(
        self, remote_path, local_path, progress=None, progress_args=()
    ):
        """Downloads file from WebDAV server and save it locally.
        More information you can find by link http://webdav.org/specs/rfc4918.html#rfc.section.9.4

        :param remote_path: the path to remote file for downloading.
        :param local_path: the path to save file locally.
        :param progress: Pass a callback function to view the file transmission progress.
                The function must take *(current, total)* as positional arguments (look at Other Parameters below for a
                detailed description) and will be called back each time a new file chunk has been successfully
                transmitted.
                `total` will be None if missing the HTTP header 'content-length' in the response from the remote.
                 Example def progress_update(current, total, *args) ...
        :param progress_args: A tuple with extra custom arguments for the progress callback function.
                You can pass anything you need to be available in the progress callback scope; for example, a Message
                object or a Client instance in order to edit the message with the updated progress status.
        """
        urn = Urn(remote_path)
        if await self.is_dir(urn.path()):
            raise OptionNotValid(name="remote_path", value=remote_path)

        if os.path.isdir(local_path):
            raise OptionNotValid(name="local_path", value=local_path)

        if not await self.check(urn.path()):
            raise RemoteResourceNotFound(urn.path())

        async with aiofiles.open(local_path, "wb") as local_file:
            response = await self.execute_request("download", urn.quote())
            clen_str = response.headers.get("content-length")
            total = int(clen_str) if clen_str is not None else None
            current = 0

            if callable(progress):
                ret = progress(current, total, *progress_args)  # zero call
                if asyncio.iscoroutine(ret):
                    await ret

            async for block in iter_content(response, self.chunk_size):
                await local_file.write(block)
                current += self.chunk_size
                if callable(progress):
                    ret = progress(current, total, *progress_args)
                    if asyncio.iscoroutine(ret):
                        await ret

    @wrap_connection_error
    async def upload_iter(self, buff: AsyncIterable, remote_path: str):
        """Uploads file from buffer to remote path on WebDAV server.
        More information you can find by link http://webdav.org/specs/rfc4918.html#METHOD_PUT

        :param callable read_callback: the read callback.
        :param str remote_path: the path to save file remotely on WebDAV server.
        """
        urn = Urn(remote_path)
        if urn.is_dir():
            raise OptionNotValid(name="remote_path", value=remote_path)

        if not await self.check(urn.parent()):
            raise RemoteParentNotFound(urn.path())

        await self.execute_request(action="upload", path=urn.quote(), data=buff)

    @wrap_connection_error
    async def upload_to(self, buff: IO, remote_path: str):
        """Uploads file from buffer to remote path on WebDAV server.
        More information you can find by link http://webdav.org/specs/rfc4918.html#METHOD_PUT

        :param buff: the buffer with content for file.
        :param remote_path: the path to save file remotely on WebDAV server.
        """
        urn = Urn(remote_path)
        if urn.is_dir():
            raise OptionNotValid(name="remote_path", value=remote_path)

        if not await self.check(urn.parent()):
            raise RemoteParentNotFound(urn.path())

        await self.execute_request(action="upload", path=urn.quote(), data=buff)

    async def upload(self, remote_path, local_path, progress=None, progress_args=()):
        """Uploads resource to remote path on WebDAV server.
        In case resource is directory it will upload all nested files and directories.
        More information you can find by link http://webdav.org/specs/rfc4918.html#METHOD_PUT

        :param remote_path: the path for uploading resources on WebDAV server. Can be file and directory.
        :param local_path: the path to local resource for uploading.
        :param progress: Pass a callback function to view the file transmission progress.
                The function must take *(current, total)* as positional arguments (look at Other Parameters below for a
                detailed description) and will be called back each time a new file chunk has been successfully
                transmitted. Example def progress_update(current, total, *args) ...
        :param progress_args: A tuple with extra custom arguments for the progress callback function.
                You can pass anything you need to be available in the progress callback scope; for example, a Message
                object or a Client instance in order to edit the message with the updated progress status.
        """
        if os.path.isdir(local_path):
            await self.upload_directory(
                local_path=local_path,
                remote_path=remote_path,
                progress=progress,
                progress_args=progress_args,
            )
        else:
            await self.upload_file(
                local_path=local_path,
                remote_path=remote_path,
                progress=progress,
                progress_args=progress_args,
            )

    async def upload_directory(
        self, remote_path, local_path, progress=None, progress_args=()
    ):
        """Uploads directory to remote path on WebDAV server.
        In case directory is exist on remote server it will delete it and then upload directory with nested files and
        directories.

        :param remote_path: the path to directory for uploading on WebDAV server.
        :param local_path: the path to local directory for uploading.
        :param progress: Pass a callback function to view the file transmission progress.
                The function must take *(current, total)* as positional arguments (look at Other Parameters below for a
                detailed description) and will be called back each time a new file chunk has been successfully
                transmitted. Example def progress_update(current, total, *args) ...
        :param progress_args: A tuple with extra custom arguments for the progress callback function.
                You can pass anything you need to be available in the progress callback scope; for example, a Message
                object or a Client instance in order to edit the message with the updated progress status.
        """
        urn = Urn(remote_path, directory=True)
        if not urn.is_dir():
            raise OptionNotValid(name="remote_path", value=remote_path)

        if not os.path.isdir(local_path):
            raise OptionNotValid(name="local_path", value=local_path)

        if not os.path.exists(local_path):
            raise LocalResourceNotFound(local_path)

        # if await self.check(urn.path()):
        #     await self.clean(urn.path()) fixme: may delete root

        await self.mkdir(remote_path)

        for resource_name in listdir(local_path):
            _remote_path = f"{urn.path()}{resource_name}".replace("\\", "")
            _local_path = os.path.join(local_path, resource_name)
            await self.upload(
                local_path=_local_path,
                remote_path=_remote_path,
                progress=progress,
                progress_args=progress_args,
            )

    @wrap_connection_error
    async def upload_file(
        self, remote_path, local_path, progress=None, progress_args=(), force=False
    ):
        """Uploads file to remote path on WebDAV server. File should be 2Gb or less.
        More information you can find by link http://webdav.org/specs/rfc4918.html#METHOD_PUT

        :param remote_path: the path to uploading file on WebDAV server.
        :param local_path: the path to local file for uploading.
        :param progress: Pass a callback function to view the file transmission progress.
                The function must take *(current, total)* as positional arguments (look at Other Parameters below for a
                detailed description) and will be called back each time a new file chunk has been successfully
                transmitted. Example def progress_update(current, total, *args) ...
        :param progress_args: A tuple with extra custom arguments for the progress callback function.
                You can pass anything you need to be available in the progress callback scope; for example, a Message
                object or a Client instance in order to edit the message with the updated progress status.
        :param force:  if the directory isn't there it will creat the directory.
        """
        if not os.path.exists(local_path):
            raise LocalResourceNotFound(local_path)

        urn = Urn(remote_path)
        if urn.is_dir():
            raise OptionNotValid(name="remote_path", value=remote_path)

        if os.path.isdir(local_path):
            raise OptionNotValid(name="local_path", value=local_path)

        if not await self.check(urn.parent()):
            if force == True:
                await self.mkdir(urn.parent(), recursive=True)
            else:
                raise RemoteParentNotFound(urn.path())

        async with aiofiles.open(local_path, "rb") as local_file:
            total = os.path.getsize(local_path)

            async def read_in_chunks(file_object):
                ret = progress(0, total, *progress_args)
                if asyncio.iscoroutine(ret):
                    await ret
                current = 0

                while current < total:
                    data = await file_object.read(self.chunk_size)
                    ret = progress(
                        current, total, *progress_args
                    )  # call to progress function
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

    @wrap_connection_error
    async def copy(self, remote_path_from, remote_path_to, depth=1):
        """Copies resource from one place to another on WebDAV server.
        More information you can find by link http://webdav.org/specs/rfc4918.html#METHOD_COPY

        :param remote_path_from: the path to resource which will be copied,
        :param remote_path_to: the path where resource will be copied.
        :param depth: folder depth to copy
        """
        urn_from = Urn(remote_path_from)
        if not await self.check(urn_from.path()):
            raise RemoteResourceNotFound(urn_from.path())

        urn_to = Urn(remote_path_to)
        if not await self.check(urn_to.parent()):
            raise RemoteParentNotFound(urn_to.path())

        headers = [f"Destination: {self.get_url(urn_to.quote())}"]
        if await self.is_dir(urn_from.path()):
            headers.append(f"Depth: {depth}")
        await self.execute_request(
            action="copy", path=urn_from.quote(), headers_ext=headers
        )

    @wrap_connection_error
    async def move(self, remote_path_from, remote_path_to, overwrite=False):
        """Moves resource from one place to another on WebDAV server.
        More information you can find by link http://webdav.org/specs/rfc4918.html#METHOD_MOVE

        :param remote_path_from: the path to resource which will be moved,
        :param remote_path_to: the path where resource will be moved.
        :param overwrite: (optional) the flag, overwrite file if it exists. Defaults is False
        """
        urn_from = Urn(remote_path_from)
        if not await self.check(urn_from.path()):
            raise RemoteResourceNotFound(urn_from.path())

        urn_to = Urn(remote_path_to)
        if not await self.check(urn_to.parent()):
            raise RemoteParentNotFound(urn_to.path())

        header_destination = f"Destination: {self.get_url(urn_to.quote())}"
        header_overwrite = "Overwrite: {flag}".format(flag="T" if overwrite else "F")
        await self.execute_request(
            action="move",
            path=urn_from.quote(),
            headers_ext=[header_destination, header_overwrite],
        )

    @wrap_connection_error
    async def clean(self, remote_path):
        """Cleans (Deletes) a remote resource on WebDAV server. The name of method is not changed for back compatibility
        with original library.
        More information you can find by link http://webdav.org/specs/rfc4918.html#METHOD_DELETE

        :param remote_path: the remote resource whisch will be deleted.
        """
        urn = Urn(remote_path)
        await self.execute_request(action="clean", path=urn.quote())

    @wrap_connection_error
    async def info(self, remote_path):
        """Gets information about resource on WebDAV.
        More information you can find by link http://webdav.org/specs/rfc4918.html#METHOD_PROPFIND

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
            content=await response.read(), path=path, hostname=self.webdav.hostname
        )

    async def _check_remote_resource(self, remote_path, urn):
        if not await self.check(urn.path()) and not await self.check(
            Urn(remote_path, directory=True).path()
        ):
            raise RemoteResourceNotFound(remote_path)

    @wrap_connection_error
    async def is_dir(self, remote_path):
        """Checks is the remote resource directory.
        More information you can find by link http://webdav.org/specs/rfc4918.html#METHOD_PROPFIND

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
            content=await response.read(), path=path, hostname=self.webdav.hostname
        )

    @wrap_connection_error
    async def get_property(self, remote_path, option):
        """Gets metadata property of remote resource on WebDAV server.
        More information you can find by link http://webdav.org/specs/rfc4918.html#METHOD_PROPFIND

        :param remote_path: the path to remote resource.
        :param option: the property attribute as dictionary with following keys:
                       `namespace`: (optional) the namespace for XML property which will be set,
                       `name`: the name of property which will be set.
        :return: the value of property or None if property is not found.
        """
        urn = Urn(remote_path)
        if not await self.check(urn.path()):
            raise RemoteResourceNotFound(urn.path())

        data = WebDavXmlUtils.create_get_property_request_content(option)
        response = await self.execute_request(
            action="get_property", path=urn.quote(), data=data
        )
        return WebDavXmlUtils.parse_get_property_response(
            await response.read(), option["name"]
        )

    @wrap_connection_error
    async def set_property(self, remote_path, option):
        """Sets metadata property of remote resource on WebDAV server.
        More information you can find by link http://webdav.org/specs/rfc4918.html#METHOD_PROPPATCH

        :param remote_path: the path to remote resource.
        :param option: the property attribute as dictionary with following keys:
                       `namespace`: (optional) the namespace for XML property which will be set,
                       `name`: the name of property which will be set,
                       `value`: (optional) the value of property which will be set. Defaults is empty string.
        """
        await self.set_property_batch(remote_path=remote_path, option=[option])

    @wrap_connection_error
    async def set_property_batch(self, remote_path, option):
        """Sets batch metadata properties of remote resource on WebDAV server in batch.
        More information you can find by link http://webdav.org/specs/rfc4918.html#METHOD_PROPPATCH

        :param remote_path: the path to remote resource.
        :param option: the property attributes as list of dictionaries with following keys:
                       `namespace`: (optional) the namespace for XML property which will be set,
                       `name`: the name of property which will be set,
                       `value`: (optional) the value of property which will be set. Defaults is empty string.
        """
        urn = Urn(remote_path)
        if not await self.check(urn.path()):
            raise RemoteResourceNotFound(urn.path())

        data = WebDavXmlUtils.create_set_property_batch_request_content(option)
        await self.execute_request(action="set_property", path=urn.quote(), data=data)

    @wrap_connection_error
    async def lock(self, remote_path=root, timeout=0):
        """Creates a lock on the given path and returns a LockClient that handles the lock.
        To ensure the lock is released this should be called using with `with client.lock("path") as c:`.
        More information at http://webdav.org/specs/rfc4918.html#METHOD_LOCK

        :param remote_path: the path to remote resource to lock.
        :param timeout: the timeout for the lock (default infinite).
        :return: LockClient that wraps the Client and handle the lock
        """
        headers_ext = None
        if timeout > 0:
            headers_ext = ["Timeout: Second-%d" % timeout]

        response = await self.execute_request(
            action="lock",
            path=Urn(remote_path).quote(),
            headers_ext=headers_ext,
            data="""<D:lockinfo xmlns:D='DAV:'><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>""",
        )

        return LockClient(
            self, Urn(remote_path).quote(), response.headers["Lock-Token"]
        )

    def resource(self, remote_path):
        """Returns a resource object for the given path.

        :param remote_path: the path to remote resource.
        :return: Resource object for the given path.
        """
        urn = Urn(remote_path)
        return Resource(self, urn)

    async def push(self, remote_directory, local_directory):
        """Pushes local directory to remote directory on WebDAV server.

        :param remote_directory: the path to remote directory for pushing.
        :param local_directory: the path to local directory for pushing.
        :return: True if local directory is more recent than remote directory, False otherwise.
        """
        def prune(src, exp):
            return [sub(exp, "", item) for item in src]

        updated = False
        urn = Urn(remote_directory, directory=True)
        await self._validate_remote_directory(urn)
        self._validate_local_directory(local_directory)

        paths = await self.list(urn.path())
        expression = "{begin}{end}".format(begin="^", end=urn.path())
        remote_resource_names = prune(paths, expression)

        for local_resource_name in listdir(local_directory):
            local_path = os.path.join(local_directory, local_resource_name)
            remote_path = f"{urn.path()}{local_resource_name}"

            if os.path.isdir(local_path):
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

    async def pull(self, remote_directory, local_directory):
        """Pulls remote directory to local directory.

        :param remote_directory: the path to remote directory for pulling.
        :param local_directory: the path to local directory for pulling.
        :return: True if remote directory is more recent than local directory, False otherwise.
        """
        def prune(src, exp):
            return [sub(exp, "", item) for item in src]

        updated = False
        urn = Urn(remote_directory, directory=True)
        await self._validate_remote_directory(urn)
        self._validate_local_directory(local_directory)

        local_resource_names = listdir(local_directory)

        paths = await self.list(urn.path())
        expression = "{begin}{end}".format(begin="^", end=remote_directory)
        remote_resource_names = prune(paths, expression)

        for remote_resource_name in remote_resource_names:
            if urn.path().endswith(remote_resource_name):
                continue
            local_path = os.path.join(local_directory, remote_resource_name)
            remote_path = f"{urn.path()}{remote_resource_name}"
            remote_urn = Urn(remote_path)

            if remote_urn.path().endswith("/"):
                if not os.path.exists(local_path):
                    updated = True
                    os.mkdir(local_path)
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

    def is_local_more_recent(self, local_path, remote_path):
        """Tells if local resource is more recent that the remote on if possible

        :param str local_path: the path to local resource.
        :param str remote_path: the path to remote resource.

        :return: True if local resource is more recent, False if the remote one is
                 None if comparison is not possible
        """
        try:
            remote_info = self.info(remote_path)
            remote_last_mod_date = remote_info["modified"]
            remote_last_mod_date = datetime.strptime(
                remote_last_mod_date, "%a, %d %b %Y %H:%M:%S %Z"
            )
            remote_last_mod_date_unix_ts = int(remote_last_mod_date.timestamp())
            local_last_mod_date_unix_ts = int(os.stat(local_path).st_mtime)

            return remote_last_mod_date_unix_ts < local_last_mod_date_unix_ts
        except (ValueError, RuntimeWarning, KeyError):
            # If there is problem when parsing dates, or cannot get
            # last modified information, return None
            return None

    async def sync(self, remote_directory, local_directory):
        """Synchronizes local and remote directories.

        :param remote_directory: the path to remote directory for synchronization.
        :param local_directory: the path to local directory for synchronization.
        """
        await self.pull(
            remote_directory=remote_directory, local_directory=local_directory
        )
        await self.push(
            remote_directory=remote_directory, local_directory=local_directory
        )

    async def publish(self, path: str):
        """Publishes resource on WebDAV server.
        More information you can find by link http://webdav.org/specs/rfc4918.html#METHOD_PUBLISH

        :param path: the path to resource for publishing.
        """
        await self.execute_request("publish", path)

    async def unpublish(self, path: str):
        """Unpublishes resource on WebDAV server.
        More information you can find by link http://webdav.org/specs/rfc4918.html

        :param path: the path to resource for unpublishing.
        """
        await self.execute_request("unpublish", path)

    async def _validate_remote_directory(self, urn):
        """Validates remote directory."""
        if not await self.is_dir(urn.path()):
            raise OptionNotValid(name="remote_path", value=urn.path())

    @staticmethod
    def _validate_local_directory(local_directory):
        """Validates local directory."""
        if not os.path.isdir(local_directory):
            raise OptionNotValid(name="local_path", value=local_directory)

        if not os.path.exists(local_directory):
            raise LocalResourceNotFound(local_directory)

    async def close(self):
        """Closes the connection to WebDAV server."""
        await self.session.close()

    async def __aenter__(self):
        """Async enter."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async exit."""
        await self.close()


class Resource:
    """Representation of resource on WebDAV server."""

    def __init__(self, client: Client, urn):
        """Representation of resource on WebDAV server."""
        self.client = client
        self.urn = urn

    def __str__(self):
        """Returns string representation of the resource."""
        return f"resource {self.urn.path()}"

    async def is_dir(self):
        """Checks is the resource directory."""
        return await self.client.is_dir(self.urn.path())

    async def rename(self, new_name):
        """Renames the resource."""
        old_path = self.urn.path()
        parent_path = self.urn.parent()
        new_name = Urn(new_name).filename()
        new_path = f"{parent_path}{new_name}"

        await self.client.move(remote_path_from=old_path, remote_path_to=new_path)
        self.urn = Urn(new_path)

    async def move(self, remote_path):
        """Moves the resource to another place."""
        new_urn = Urn(remote_path)
        await self.client.move(
            remote_path_from=self.urn.path(), remote_path_to=new_urn.path()
        )
        self.urn = new_urn

    async def copy(self, remote_path):
        """Copies the resource to another place."""
        urn = Urn(remote_path)
        await self.client.copy(
            remote_path_from=self.urn.path(), remote_path_to=remote_path
        )
        return Resource(self.client, urn)

    async def info(self, params=None):
        """Gets information about resource on WebDAV."""
        info = await self.client.info(self.urn.path())
        if not params:
            return info

        return {key: value for (key, value) in info.items() if key in params}

    async def clean(self):
        """Cleans (Deletes) the resource."""
        return await self.client.clean(self.urn.path())

    async def check(self):
        """Checks is the resource exists."""
        return await self.client.check(self.urn.path())

    async def read_from(self, buff):
        """Reads the resource to buffer."""
        await self.client.upload_to(buff=buff, remote_path=self.urn.path())

    async def read(self, local_path):
        """Reads the resource to local path."""
        return await self.client.upload(
            local_path=local_path, remote_path=self.urn.path()
        )

    async def write_to(self, buff):
        """Writes the buffer to the resource."""
        return await self.client.download_from(buff=buff, remote_path=self.urn.path())

    async def write(self, local_path):
        """Writes the local path to the resource."""
        return await self.client.download(
            local_path=local_path, remote_path=self.urn.path()
        )

    async def publish(self):
        """Publishes the resource."""
        return await self.client.publish(self.urn.path())

    async def unpublish(self):
        """Unpublishes the resource."""
        return await self.client.unpublish(self.urn.path())

    async def get_property(self, option):
        """Gets metadata property of the resource."""
        return await self.client.get_property(
            remote_path=self.urn.path(), option=option
        )

    async def set_property(self, option, value):
        """Sets metadata property of the resource."""
        option["value"] = value.__str__()
        await self.client.set_property(remote_path=self.urn.path(), option=option)


class WebDavXmlUtils:
    """WebDAV XML utils."""

    @staticmethod
    def parse_get_list_info_response(content):
        """Parses of response content XML from WebDAV server and extract file and directory infos

        :param content: the XML content of HTTP response from WebDAV server for getting list of files by remote path.
        :return: list of information, the information is a dictionary and it values with following keys:
                 `created`: date of resource creation,
                 `name`: name of resource,
                 `size`: size of resource,
                 `modified`: date of resource modification,
                 `etag`: etag of resource,
                 `content_type`: content type of resource,
                 `isdir`: type of resource,
                 `path`: path of resource.
        """
        try:
            tree = etree.fromstring(content)
            infos = []
            for response in tree.findall(".//{DAV:}response"):
                href_el = next(iter(response.findall(".//{DAV:}href")), None)
                if href_el is None:
                    continue
                path = unquote(urlsplit(href_el.text).path)
                info = dict()
                is_dir = len(response.findall(".//{DAV:}collection")) > 0
                info = WebDavXmlUtils.get_info_from_response(response)
                info["isdir"] = is_dir
                info["path"] = path
                infos.append(info)
            return infos
        except etree.XMLSyntaxError:
            return list()

    @staticmethod
    def parse_get_list_response(content):
        """Parses of response content XML from WebDAV server and extract file and directory names.

        :param content: the XML content of HTTP response from WebDAV server for getting list of files by remote path.
        :return: list of extracted file or directory names.
        """
        try:
            tree = etree.fromstring(content)
            urns = []
            for response in tree.findall(".//{DAV:}response"):
                href_el = next(iter(response.findall(".//{DAV:}href")), None)
                if href_el is None:
                    continue
                href = Urn.separate + unquote(urlsplit(href_el.text).path)
                is_dir = len(response.findall(".//{DAV:}collection")) > 0
                urns.append(Urn(href, is_dir))
            return urns
        except etree.XMLSyntaxError:
            return list()

    @staticmethod
    def create_free_space_request_content() -> bytes:
        """Creates an XML for requesting of free space on remote WebDAV server.

        :return: the XML string of request content.
        """
        root = etree.Element("propfind", xmlns="DAV:")
        prop = etree.SubElement(root, "prop")
        etree.SubElement(prop, "quota-available-bytes")
        etree.SubElement(prop, "quota-used-bytes")
        tree = etree.ElementTree(root)
        return WebDavXmlUtils.etree_to_string(tree)

    @staticmethod
    def parse_free_space_response(content, hostname):
        """Parses of response content XML from WebDAV server and extract an amount of free space.

        :param content: the XML content of HTTP response from WebDAV server for getting free space.
        :param hostname: the server hostname.
        :return: an amount of free space in bytes.
        """
        try:
            tree = etree.fromstring(content)
            node = tree.find(".//{DAV:}quota-available-bytes")
            if node is not None:
                return int(node.text)
            raise MethodNotSupported(name="free", server=hostname)
        except TypeError:
            raise MethodNotSupported(name="free", server=hostname)
        except etree.XMLSyntaxError:
            return ""

    @staticmethod
    def get_info_from_response(response):
        """Get information attributes from response

        :param response: XML object of response for the remote resource defined by path
        :return: a dictionary of information attributes and them values with following keys:
                 `created`: date of resource creation,
                 `name`: name of resource,
                 `size`: size of resource,
                 `modified`: date of resource modification,
                 `etag`: etag of resource,
                 `content_type`: content type of resource.
        """
        find_attributes = {
            "created": ".//{DAV:}creationdate",
            "name": ".//{DAV:}displayname",
            "size": ".//{DAV:}getcontentlength",
            "modified": ".//{DAV:}getlastmodified",
            "etag": ".//{DAV:}getetag",
            "content_type": ".//{DAV:}getcontenttype",
        }
        info = dict()
        for name, value in find_attributes.items():
            info[name] = response.findtext(value)
        return info

    @staticmethod
    def parse_info_response(content, path, hostname):
        """Parses of response content XML from WebDAV server and extract an information about resource.

        :param content: the XML content of HTTP response from WebDAV server.
        :param path: the path to resource.
        :param hostname: the server hostname.
        :return: a dictionary of information attributes and them values with following keys:
                 `created`: date of resource creation,
                 `name`: name of resource,
                 `size`: size of resource,
                 `modified`: date of resource modification,
                 `etag`: etag of resource,
                 `content_type`: content type of resource.
        """
        response = WebDavXmlUtils.extract_response_for_path(
            content=content, path=path, hostname=hostname
        )
        return WebDavXmlUtils.get_info_from_response(response)

    @staticmethod
    def parse_is_dir_response(content, path, hostname):
        """Parses of response content XML from WebDAV server and extract an information about resource.

        :param content: the XML content of HTTP response from WebDAV server.
        :param path: the path to resource.
        :param hostname: the server hostname.
        :return: True in case the remote resource is directory and False otherwise.
        """
        response = WebDavXmlUtils.extract_response_for_path(
            content=content, path=path, hostname=hostname
        )
        resource_type = response.find(".//{DAV:}resourcetype")
        if resource_type is None:
            raise MethodNotSupported(name="is_dir", server=hostname)
        dir_type = resource_type.find("{DAV:}collection")

        return True if dir_type is not None else False

    @staticmethod
    def create_get_property_request_content(option):
        """Creates an XML for requesting of getting a property value of remote WebDAV resource.

        :param option: the property attributes as dictionary with following keys:
                       `namespace`: (optional) the namespace for XML property which will be get,
                       `name`: the name of property which will be get.
        :return: the XML string of request content.
        """
        root = etree.Element("propfind", xmlns="DAV:")
        prop = etree.SubElement(root, "prop")
        etree.SubElement(
            prop, option.get("name", ""), xmlns=option.get("namespace", "")
        )
        tree = etree.ElementTree(root)
        return WebDavXmlUtils.etree_to_string(tree)

    @staticmethod
    def parse_get_property_response(content, name):
        """Parses of response content XML from WebDAV server for getting metadata property value for some resource.

        :param content: the XML content of response as string.
        :param name: the name of property for finding a value in response
        :return: the value of property if it has been found or None otherwise.
        """
        tree = etree.fromstring(content)
        return tree.xpath("//*[local-name() = $name]", name=name)[0].text

    @staticmethod
    def create_set_property_batch_request_content(options):
        """Creates an XML for requesting of setting a property values for remote WebDAV resource in batch.

        :param options: the property attributes as list of dictionaries with following keys:
                       `namespace`: (optional) the namespace for XML property which will be set,
                       `name`: the name of property which will be set,
                       `value`: (optional) the value of property which will be set. Defaults is empty string.
        :return: the XML string of request content.
        """
        root_node = etree.Element("propertyupdate", xmlns="DAV:")
        set_node = etree.SubElement(root_node, "set")
        prop_node = etree.SubElement(set_node, "prop")
        for option in options:
            opt_node = etree.SubElement(
                prop_node, option["name"], xmlns=option.get("namespace", "")
            )
            opt_node.text = option.get("value", "")
        tree = etree.ElementTree(root_node)
        return WebDavXmlUtils.etree_to_string(tree)

    @staticmethod
    def etree_to_string(tree):
        """Creates string from lxml.etree.ElementTree with XML declaration and UTF-8 encoding.

        :param tree: the instance of ElementTree
        :return: the string of XML.
        """
        buff = BytesIO()
        tree.write(buff, xml_declaration=True, encoding="UTF-8")
        return buff.getvalue()

    @staticmethod
    def extract_response_for_path(content, path, hostname):
        """Extracts single response for specified remote resource.

        :param content: raw content of response as string.
        :param path: the path to needed remote resource.
        :param hostname: the server hostname.
        :return: XML object of response for the remote resource defined by path.
        """
        prefix = urlparse(hostname).path
        try:
            tree = etree.fromstring(content)
            responses = tree.findall("{DAV:}response")
            n_path = Urn.normalize_path(path)

            for resp in responses:
                href = resp.findtext("{DAV:}href")

                if Urn.compare_path(n_path, href) is True:
                    return resp
                href_without_prefix = href.removeprefix(prefix)
                if Urn.compare_path(n_path, href_without_prefix) is True:
                    return resp
            raise RemoteResourceNotFound(path)
        except etree.XMLSyntaxError:
            raise MethodNotSupported(name="is_dir", server=hostname)


class LockClient(Client):
    """Client for handling locks on WebDAV server."""

    def __init__(self, client, lock_path, lock_token):
        """Client for handling locks on WebDAV server."""
        super().__init__([])
        self.session = client.session
        self.webdav = client.webdav
        self.requests = client.requests
        self.timeout = self.webdav.timeout

        self.__lock_path = lock_path
        self.__lock_token = lock_token

    def get_headers(self, action, headers_ext=None):
        """Gets headers for request to WebDAV server."""
        headers = super().get_headers(action, headers_ext)
        headers["Lock-Token"] = self.__lock_token
        headers["If"] = "(%s)" % self.__lock_token
        return headers

    async def __aenter__(self):
        """Async enter."""
        await self.execute_request(action="lock", path=self.__lock_path)
        return await super().__aenter__()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async exit."""
        await super().__aexit__()
        await self.execute_request(action="unlock", path=self.__lock_path)
