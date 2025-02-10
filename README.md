aiowebdav2
=========
[![GitHub Release][releases-shield]][releases]
[![Python Versions][python-versions-shield]][pypi]
![Project Stage][project-stage-shield]
![Project Maintenance][maintenance-shield]
[![License][license-shield]](LICENSE.md)

[![Build Status][build-shield]][build]
[![Code Coverage][codecov-shield]][codecov]

`aiowebdav2` is an asyncio based Python 3 client for WebDAV.

It is based on https://github.com/designerror/webdav-client-python and https://github.com/synodriver/aiowebdav.

Installation
------------
```bash
$ pip install aiowebdav2
```

Sample Usage
------------

```python
import asyncio
from aiowebdav2.client import Client

options = {
 'webdav_hostname': "https://webdav.server.ru",
 'webdav_login': "login",
 'webdav_password': "password",
 "disable_check": True
}

async def main():
    client = Client(options)
    client.verify = False  # To not check SSL certificates (Default = True)
    await client.execute_request("mkdir", 'directory_name')
asyncio.run(main())
```

Webdav API
==========

Webdav API is a set of webdav actions of work with cloud storage. This set includes the following actions:
`check`, `free`, `info`, `list`, `mkdir`, `clean`, `copy`, `move`, `download`, `upload`, `publish` and `unpublish`.

**Configuring the client**

Required key is host name or IP address of the WevDAV-server with param name `webdav_hostname`.
For authentication in WebDAV server use `webdav_login`, `webdav_password`.
For an anonymous login do not specify auth properties.

```python
from aiowebdav2.client import Client

options = {
 'webdav_hostname': "https://webdav.server.ru",
 'webdav_login': "login",
 'webdav_password': "password"
}
client = Client(options)
```

If your server does not support `HEAD` method or there are other reasons to override default WebDAV methods for actions use a dictionary option `webdav_override_methods`.
The key should be in the following list: `check`, `free`, `info`, `list`, `mkdir`, `clean`, `copy`, `move`, `download`, `upload`,
 `publish` and `unpublish`. The value should a string name of WebDAV method, for example `GET`.

```python
from aiowebdav2.client import Client

options = {
 'webdav_hostname': "https://webdav.server.ru",
 'webdav_login': "login",
 'webdav_password': "password",
 'webdav_override_methods': {
  'check': 'GET'
 }

}
client = Client(options)
```

For configuring a requests timeout you can use an option `webdav_timeout` with int value in seconds, by default the timeout is set to 30 seconds.

```python
from aiowebdav2.client import Client

options = {
 'webdav_hostname': "https://webdav.server.ru",
 'webdav_login': "login",
 'webdav_password': "password",
 'webdav_timeout': 30
}
client = Client(options)
```

When a proxy server you need to specify settings to connect through it.

```python
from aiowebdav2.client import Client

options = {
 'webdav_hostname': "https://webdav.server.ru",
 'webdav_login': "w_login",
 'webdav_password': "w_password",
 'webdav_proxy': "http://127.0.0.1:8080",
 'webdav_proxy_auth': "xxx",
}
client = Client(options)
```

If you want to use the certificate path to certificate and private key is defined as follows:

```python
from aiowebdav2.client import Client

options = {
 'webdav_hostname': "https://webdav.server.ru",
 'webdav_login': "w_login",
 'webdav_password': "w_password",
 'webdav_ssl': 'sslcontext'
}
client = Client(options)
```

Or you want to limit the speed or turn on verbose mode:

```python
options = {
 ...
 'recv_speed' : 3000000,
 'send_speed' : 3000000,
 'verbose'    : True
}
client = Client(options)
```

recv_speed: rate limit data download speed in Bytes per second. Defaults to unlimited speed.
send_speed: rate limit data upload speed in Bytes per second. Defaults to unlimited speed.
verbose:    set verbose mode on/off. By default verbose mode is off.

Also if your server does not support `check` it is possible to disable it:

```python
options = {
 ...
 'disable_check': True
}
client = Client(options)
```

By default, checking of remote resources is enabled.

For configuring chunk size of content downloading use `chunk_size` param, by default it is `65536`

```python
options = {
 ...
 'chunk_size': 65536
}
client = Client(options)
```

**Asynchronous methods**

```python
# Checking existence of the resource

await client.check("dir1/file1")
await client.check("dir1")
```

```python
# Get information about the resource

await client.info("dir1/file1")
await client.info("dir1/")
```

```python
# Check free space

free_size = await client.free()
```

```python
# Get a list of resources

files1 = await client.list()
files2 = await client.list("dir1")
files3 = await client.list("dir1", get_info=True) # returns a list of dictionaries with files details
```

```python
# Create directory

await client.mkdir("dir1/dir2")
```

```python
# Delete resource

await client.clean("dir1/dir2")
```

```python
# Copy resource

await client.copy(remote_path_from="dir1/file1", remote_path_to="dir2/file1")
await client.copy(remote_path_from="dir2", remote_path_to="dir3")
```

```python
# Move resource

await client.move(remote_path_from="dir1/file1", remote_path_to="dir2/file1")
await client.move(remote_path_from="dir2", remote_path_to="dir3")
```

```python
# Download a resource

await client.download(remote_path="dir1/file1", local_path="~/Downloads/file1")
await client.download(remote_path="dir1/dir2/", local_path="~/Downloads/dir2/")
```

```python
# Upload resource

await client.upload(remote_path="dir1/file1", local_path="~/Documents/file1")
await client.upload(remote_path="dir1/dir2/", local_path="~/Documents/dir2/")
```

```python
# Publish the resource

link = await client.publish("dir1/file1")
link = await client.publish("dir2")
```

```python
# Unpublish resource

await client.unpublish("dir1/file1")
await client.unpublish("dir2")
```

```python
# Exception handling

from aiowebdav.exceptions import WebDavException

try:
 ...
except WebDavException as exception:
...
```

```python
# Get the missing files

await client.pull(remote_directory='dir1', local_directory='~/Documents/dir1')
```

```python
# Send missing files

await client.push(remote_directory='dir1', local_directory='~/Documents/dir1')
```

```python
# Unload resource

kwargs = {
 'remote_path': "dir1/file1",
 'local_path':  "~/Downloads/file1",
 'callback':    callback
}
client.upload_async(**kwargs)

kwargs = {
 'remote_path': "dir1/dir2/",
 'local_path':  "~/Downloads/dir2/",
 'callback':    callback
}
client.upload_async(**kwargs)
```

Resource API
============

Resource API using the concept of OOP that enables cloud-level resources.

```python
# Get a resource

res1 = client.resource("dir1/file1")
```

```python
# Work with the resource

await res1.rename("file2")
await res1.move("dir1/file2")
await res1.copy("dir2/file1")
info = await res1.info()
await res1.read_from(buffer)
await res1.read(local_path="~/Documents/file1")
await res1.write_to(buffer)
await res1.write(local_path="~/Downloads/file1")

```

## Changelog & Releases

This repository keeps a change log using [GitHub's releases][releases]
functionality. The format of the log is based on
[Keep a Changelog][keepchangelog].

Releases are based on [Semantic Versioning][semver], and use the format
of `MAJOR.MINOR.PATCH`. In a nutshell, the version will be incremented
based on the following:

- `MAJOR`: Incompatible or major changes.
- `MINOR`: Backwards-compatible new features and enhancements.
- `PATCH`: Backwards-compatible bugfixes and package updates.

## Contributing

This is an active open-source project. I am always open to people who want to
use the code or contribute to it.

Thank you for being involved! :heart_eyes:

## Setting up development environment

This Python project is fully managed using the [Poetry][poetry] dependency manager. But also relies on the use of NodeJS for certain checks during development.

You need at least:

- Python 3.11+
- [Poetry][poetry-install]
- NodeJS 20+ (including NPM)

To install all packages, including all development requirements:

```bash
npm install
poetry install
```

As this repository uses the [pre-commit][pre-commit] framework, all changes
are linted and tested with each commit. You can run all checks and tests
manually, using the following command:

```bash
poetry run pre-commit run --all-files
```

To run just the Python tests:

```bash
poetry run pytest
```

## Authors & contributors

The content is by [Jan-Philipp Benecke][jpbede].

For a full list of all authors and contributors,
check [the contributor's page][contributors].

## License

MIT License

Copyright (c) 2025 Jan-Philipp Benecke

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

[build-shield]: https://github.com/jpbede/aiowebdav2/actions/workflows/release.yml/badge.svg
[build]: https://github.com/jpbede/aiowebdav2/actions
[codecov-shield]: https://codecov.io/gh/jpbede/aiowebdav2/branch/main/graph/badge.svg
[codecov]: https://codecov.io/gh/jpbede/aiowebdav2
[commits-shield]: https://img.shields.io/github/commit-activity/y/jpbede/aiowebdav2.svg
[commits]: https://github.com/jpbede/aiowebdav2/commits/main
[contributors]: https://github.com/jpbede/aiowebdav2/graphs/contributors
[jpbede]: https://github.com/jpbede
[keepchangelog]: http://keepachangelog.com/en/1.0.0/
[license-shield]: https://img.shields.io/github/license/jpbede/aiowebdav2.svg
[maintenance-shield]: https://img.shields.io/maintenance/yes/2025.svg
[poetry-install]: https://python-poetry.org/docs/#installation
[poetry]: https://python-poetry.org
[pre-commit]: https://pre-commit.com/
[project-stage-shield]: https://img.shields.io/badge/project%20stage-stable-green.svg
[python-versions-shield]: https://img.shields.io/pypi/pyversions/aiowebdav2
[releases-shield]: https://img.shields.io/github/release/jpbede/aiowebdav2.svg
[releases]: https://github.com/jpbede/aiowebdav2/releases
[semver]: http://semver.org/spec/v2.0.0.html
[pypi]: https://pypi.org/project/aiowebdav2/
