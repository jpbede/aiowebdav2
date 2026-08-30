# AGENTS.md

> Guidelines for AI coding agents working in the `aiowebdav2` repository.

## Project Overview

Async Python WebDAV client library. Python 3.13+, fully typed (`py.typed`), published to PyPI.
Package source lives in `aiowebdav2/`, tests in `tests/`.

The 1.0 API is intentionally breaking and has clear ownership boundaries:

- `aiowebdav2.client.Client` is remote-only WebDAV behavior.
- `aiowebdav2.filesystem` owns local filesystem transfers.
- `aiowebdav2._http` owns aiohttp transport, auth headers, proxy options, and
  status-code mapping.
- `aiowebdav2._xml` owns XML bytes/document boundaries and parser safety policy.
- `aiowebdav2.models` owns model parsing and XML serialization.
- `aiowebdav2._paths` owns path and URL normalization helpers.

Do not reintroduce the old monolithic client shape (`Resource`, `LockClient`,
`execute_request`, `list_files`, `download_file`, `upload_file`, `clean`, or
`check` on `Client`). Add remote operations to `Client`; add local transfer
helpers to `filesystem.py`.

## Build & Environment

```bash
# Install dependencies (requires uv - https://docs.astral.sh/uv/)
uv sync --group dev

# Node.js (only for Prettier on non-Python files)
npm install
```

## Test Commands

```bash
# Run all tests (--cov is in addopts by default)
uv run pytest

# Run a single test file
uv run pytest tests/test_client.py

# Run a single test function (use --no-cov for speed)
uv run pytest tests/test_client.py::test_list_and_stat -v --no-cov

# Run tests matching a keyword pattern
uv run pytest -k "test_quota" --no-cov

# Run a specific parametrized case
uv run pytest tests/test_client.py::test_status_errors -k "401" --no-cov
```

**Important:** `asyncio_mode = "auto"` — async test functions are detected automatically.
No `@pytest.mark.asyncio` decorator needed.

## Lint & Format Commands

```bash
# Linting
uv run ruff check .                  # Lint (all rules enabled)
uv run ruff check --fix .            # Lint with auto-fix
uv run ruff format .                 # Format Python code
uv run ruff format --check .         # Check formatting without modifying

# Type checking (strict mode)
uv run mypy aiowebdav2

# Additional linters
uv run pylint aiowebdav2             # Pylint (ignores tests/)
uv run codespell --ignore-words-list=fo,incomfort,nam,bloc,ue
uv run yamllint .

# Non-Python formatting (JSON, YAML, Markdown)
npm run prettier
```

## Pre-commit Hooks

Uses `prek` (not `pre-commit`). Run all hooks: `uv run prek run --all-files`.

## Code Style

### Formatting

- **Formatter:** Ruff (`ruff format`)
- **Line length:** 88 characters
- **Indentation:** 4 spaces
- **Quotes:** Double quotes (`"`)
- **Trailing commas:** On multi-line structures
- **End of file:** Single newline, no trailing whitespace

### Imports

Three groups separated by blank lines, sorted alphabetically within each:

```python
import asyncio  # 1. Standard library
from pathlib import Path

from aiohttp import ClientTimeout  # 2. Third-party
from lxml import etree

from .exceptions import WebDavError  # 3. Local (relative imports)
from .models import Property
```

- Use **relative imports** within the `aiowebdav2` package
- Use **absolute imports** in tests (`from aiowebdav2 import Client`)
- Test helpers use relative imports (`from . import load_responses`)

### Type Annotations

- **All functions** must have full type annotations including return types
- Use modern union syntax: `str | None` (not `Optional[str]`)
- Use `collections.abc` for abstract types: `AsyncIterable`, `Callable`, `Generator`
- Use `typing` for special forms: `IO`, `Any`, `ClassVar`, `Self`, `Protocol`
- Mypy runs in strict mode — no untyped defs, no `Any` generics, strict optional

### Naming Conventions

| Element           | Convention           | Example                                 |
| ----------------- | -------------------- | --------------------------------------- |
| Variables         | `snake_case`         | `remote_path`, `local_file`             |
| Functions/methods | `snake_case`         | `list()`, `download_file()`             |
| Private members   | `_snake_case`        | `_list_raw()`, `_get_auth()`            |
| Classes           | `PascalCase`         | `Client`, `ClientOptions`               |
| Exceptions        | `PascalCase + Error` | `WebDavError`, `NoConnectionError`      |
| Constants         | `UPPER_SNAKE_CASE`   | `DEFAULT_ROOT = "/"`                    |
| Module loggers    | `_LOGGER`            | `_LOGGER = logging.getLogger(__name__)` |
| Files/directories | `snake_case`         | `filesystem.py`, `test_client.py`       |

### Dataclasses

Always use the strict configuration:

```python
@dataclass(frozen=True, slots=True, kw_only=True)
class ClientOptions:
    chunk_size: int = 65536
```

### Error Handling

- Custom exception hierarchy rooted in `WebDavError` (see `exceptions.py`)
- Map HTTP status codes to specific exceptions in request handling
- Use exception chaining: `raise NoConnectionError(url) from err`
- Assign error messages to `msg` before raising:
  ```python
  msg = f"module {__name__!r} has no attribute {name!r}"
  raise AttributeError(msg)
  ```

### Logging

Use `%s` placeholders (not f-strings) for lazy evaluation:

```python
_LOGGER.debug("Request to %s with method %s", url, method)
```

### String Formatting

Use f-strings for everything except logging:

```python
f"Bearer {self._options.token}"
```

### Exports

- Explicit `__all__` in `__init__.py` listing every public symbol
- `__init__.py` re-exports from submodules (barrel pattern)

## 1.0 API Boundaries

- `Client` public remote methods are `url`, `request`, `exists`, `stat`,
  `is_dir`, `list`, `mkdir`, `delete`, `copy`, `move`, `read`, `iter_read`,
  `write`, `quota`, `get_property`, `get_properties`, `list_properties`,
  `set_property`, `set_properties`, `lock`, `unlock`, and `close`.
- Local transfer helpers are public functions in `aiowebdav2.filesystem`:
  `download_file`, `upload_file`, `download_tree`, and `upload_tree`.
  They depend on the optional `aiowebdav2[filesystem]` extra.
- Do not accept or pass `aiohttp.BasicAuth`. aiohttp v4 deprecates it for this
  use case. Basic auth is generated internally from `username` and `password`
  using the standard library. Bearer auth uses `ClientOptions(token=...)`.
- Do not add `proxy_auth`; proxy credentials must be supplied through
  `ClientOptions(proxy_headers=...)`.
- Prefer the standard library over new dependencies. `aiofiles` is only used by
  the optional local filesystem transfer helpers; do not re-add
  `python-dateutil` unless there is a measured reason.

## XML & Models

- Use `lxml` for XML support, with minimum version `lxml>=6.1.0`.
- All XML byte parsing goes through `_xml.parse_xml`, which enforces
  `resolve_entities=False`, `no_network=True`, `load_dtd=False`, and
  `huge_tree=False`.
- Do not call `etree.fromstring` directly outside `_xml.parse_xml`.
- Keep parsing and serialization close to the public models:
  `ResourceInfo.from_response`, `QuotaInfo.from_element`,
  `Property.from_response`, `PropertyRequest.append_to`, and
  `Property.append_to`.
- `_xml.py` should stay a thin WebDAV XML boundary: build request documents,
  call `parse_xml`, iterate WebDAV response elements, and delegate extraction to
  models.

## Testing Conventions

- **Framework:** pytest with `pytest-asyncio` (auto mode) and `aiointercept`
- **File naming:** `test_<module_name>.py` mirroring source modules
- **Docstrings:** Every test function must have a one-line docstring
- **Assertions:** Plain `assert` statements (no `self.assertEqual`)
- **Exception testing:** `pytest.raises` with `match=` parameter
- **Parametrize:** `@pytest.mark.parametrize` with tuple-based test IDs
- **Fixtures:** Defined in `conftest.py`, use `name=` parameter for renaming
- **HTTP mocking:** `aiointercept` library (not `unittest.mock`)
- **Test data:** XML fixtures in `tests/responses/`, loaded via `load_responses()`
- **Coverage:** Minimum 50% enforced (`fail_under = 50`)

```python
async def test_list_and_stat(client: Client, responses: aiointercept) -> None:
    """Test listing and stat."""
    url = "https://webdav.example.com/test_dir/"
    responses.add(url, "PROPFIND", status=200, body=load_responses("get_list.xml"))
    resources = await client.list("/test_dir/")
    assert len(resources) == 2
```

### Test-specific Ruff Overrides (`tests/ruff.toml`)

Tests allow: `assert` statements, password detection strings, private member
access, moving type-only imports used by pytest (`TC002`), and overwriting
functions with many arguments (`PLR0913`).

## CI/CD

GitHub Actions includes PR/push workflows and release-only workflows:

- **tests.yml** — pytest on Python 3.13, 3.14, 3.15
- **linting.yml** — ruff, codespell, pylint, yamllint, prettier
- **typing.yml** — mypy strict checking
- **release.yml** — builds and publishes to PyPI on GitHub release (`release.published`)
