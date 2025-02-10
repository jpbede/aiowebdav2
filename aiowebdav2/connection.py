"""WebDAV connection settings."""

from collections.abc import Mapping
import ssl
from typing import TYPE_CHECKING, ClassVar

import aiohttp

from aiowebdav2.exceptions import OptionNotValidError
from aiowebdav2.urn import Urn

if TYPE_CHECKING:
    from pathlib import Path


class ConnectionSettings:
    """Base class for connection settings."""

    def is_valid(self) -> bool:
        """Check settings are valid.

        :return: True if settings are valid otherwise False.
        """
        return True

    def valid(self) -> bool:
        """Check if settings are valid."""
        try:
            self.is_valid()
        except OptionNotValidError:
            return False

        return True


class WebDAVSettings(ConnectionSettings):
    """WebDAV connection settings."""

    ns = "webdav:"
    prefix = "webdav_"
    keys: ClassVar[list[str]] = [
        "hostname",
        "login",
        "password",
        "token",
        "root",
        "ssl",
        "recv_speed",
        "send_speed",
        "verbose",
        "disable_check",
        "override_methods",
        "timeout",
        "chunk_size",
        "proxy",
        "proxy_auth",
    ]

    def __init__(self, options: Mapping[str, str | int | bool | None]) -> None:
        """WebDAV connection settings."""
        self.hostname: str = ""
        self.login = None
        self.password = None
        self.token = None
        self.root = "/"
        self.ssl: ssl.SSLContext = ssl.create_default_context()
        self.recv_speed = None
        self.send_speed = None
        self.verbose = None
        self.disable_check = False
        self.override_methods: dict[str, str] = {}
        self.timeout = aiohttp.ClientTimeout(total=30)
        self.chunk_size = 65536
        self.proxy = None
        self.proxy_auth = None
        self.cert_path: Path | None = None
        self.key_path: Path | None = None

        self.options = {}

        for key in self.keys:
            value = options.get(key, "")
            if not (self.__dict__[key] and not value):
                self.options[key] = value
                self.__dict__[key] = value

        self.root = Urn(self.root).quote() if self.root else "/"
        self.root = self.root.rstrip(Urn.separate)
        self.hostname = self.hostname.rstrip(Urn.separate) if self.hostname else ""
        if isinstance(self.timeout, int | float):
            self.timeout = aiohttp.ClientTimeout(self.timeout)

    def is_valid(self) -> bool:
        """Check settings are valid."""
        if not self.hostname:
            raise OptionNotValidError(
                name="hostname", value=str(self.hostname), ns=self.ns
            )

        if self.cert_path and not self.cert_path.exists():
            raise OptionNotValidError(
                name="cert_path", value=str(self.cert_path), ns=self.ns
            )

        if self.key_path and not self.key_path.exists():
            raise OptionNotValidError(
                name="key_path", value=str(self.key_path), ns=self.ns
            )

        if self.key_path and not self.cert_path:
            raise OptionNotValidError(
                name="cert_path", value=str(self.cert_path), ns=self.ns
            )

        if self.password and not self.login:
            raise OptionNotValidError(name="login", value=self.login, ns=self.ns)
        return True
