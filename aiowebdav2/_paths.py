"""Remote path and URL helpers."""

from posixpath import normpath
from urllib.parse import unquote, urlsplit

import yarl

from .exceptions import OptionNotValidError


def _has_relative_component(path: str) -> bool:
    decoded_path = unquote(_path_part(path))
    return any(part in {".", ".."} for part in decoded_path.split("/"))


def _reject_relative_components(name: str, path: str) -> None:
    if _has_relative_component(path):
        raise OptionNotValidError(name=name, value=path)


def normalize_path(path: str, *, directory: bool = False) -> str:
    """Normalize a remote WebDAV path."""
    decoded_path = unquote(_path_part(path))
    trailing_slash = decoded_path.endswith("/")

    if not decoded_path.startswith("/"):
        decoded_path = f"/{decoded_path}"

    normalized = normpath(decoded_path)
    if normalized == ".":
        normalized = "/"
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"

    if normalized == "/":
        return normalized
    if directory or trailing_slash:
        return f"{normalized.rstrip('/')}/"
    return normalized


def parent_path(path: str) -> str:
    """Return the parent directory for a remote path."""
    normalized = normalize_path(path).rstrip("/")
    parent = normalized.rsplit("/", 1)[0]
    return "/" if not parent else f"{parent}/"


def basename(path: str) -> str:
    """Return the final path component for a remote path."""
    normalized = normalize_path(path)
    if normalized == "/":
        return ""
    return normalized.rstrip("/").rsplit("/", 1)[-1]


def join_url(base_url: str, root: str, path: str) -> str:
    """Join base URL, configured root, and remote path."""
    url = yarl.URL(base_url)
    _reject_relative_components("base_url", url.path)
    _reject_relative_components("root", root)
    _reject_relative_components("path", path)
    parts = [url.path.strip("/"), root.strip("/"), path.strip("/")]
    joined = "/".join(part for part in parts if part)
    full_path = normalize_path(f"/{joined}", directory=path.endswith("/"))
    return str(url.with_path(full_path))


def base_path(base_url: str, root: str) -> str:
    """Return the URL path prefix hidden from public paths."""
    url = yarl.URL(base_url)
    parts = [url.path.strip("/"), root.strip("/")]
    joined = "/".join(part for part in parts if part)
    return normalize_path(f"/{joined}", directory=True)


def strip_base(path: str, prefix: str, *, directory: bool = False) -> str:
    """Strip a configured base path from a server href."""
    normalized_path = normalize_path(path, directory=directory)
    normalized_prefix = normalize_path(prefix, directory=True)

    if normalized_path.rstrip("/") == normalized_prefix.rstrip("/"):
        return "/"
    if normalized_path.startswith(normalized_prefix):
        stripped = normalized_path.removeprefix(normalized_prefix)
        return normalize_path(stripped or "/", directory=directory)
    return normalized_path


def same_path(left: str, right: str) -> bool:
    """Compare remote paths after URL decoding and normalization."""
    return _comparison_path(left) == _comparison_path(right)


def _comparison_path(path: str) -> str:
    normalized = normalize_path(path)
    if normalized == "/":
        return normalized
    return normalized.rstrip("/")


def _path_part(path: str) -> str:
    parsed = urlsplit(path)
    if parsed.scheme or parsed.netloc:
        return parsed.path
    return path
