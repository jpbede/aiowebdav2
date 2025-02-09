"""URN module for aiowebdav2."""
from re import sub
from urllib.parse import quote, unquote, urlsplit


class Urn:
    """Class for URN representation."""

    separate = "/"

    def __init__(self, path, directory=False):
        """Class for URN representation."""
        self._path = quote(path)
        expressions = r"/\.+/", "/+"
        for expression in expressions:
            self._path = sub(expression, Urn.separate, self._path)

        if not self._path.startswith(Urn.separate):
            self._path = f"{Urn.separate}{self._path}"

        if directory and not self._path.endswith(Urn.separate):
            self._path = f"{self._path}{Urn.separate}"

    def __str__(self):
        """Return string representation of URN."""
        return self.path()

    def path(self):
        """Return path."""
        return unquote(self._path)

    def quote(self):
        """Return quoted path."""
        return self._path

    def filename(self):
        """Return filename."""
        path_split = self._path.split(Urn.separate)
        name = path_split[-2] + Urn.separate if path_split[-1] == "" else path_split[-1]
        return unquote(name)

    def parent(self):
        """Return parent path."""
        path_split = self._path.split(Urn.separate)
        nesting_level = self.nesting_level()
        parent_path_split = path_split[:nesting_level]
        parent = (
            self.separate.join(parent_path_split)
            if nesting_level != 1
            else Urn.separate
        )
        if not parent.endswith(Urn.separate):
            return unquote(parent + Urn.separate)
        return unquote(parent)

    def nesting_level(self):
        """Return nesting level."""
        return self._path.count(Urn.separate, 0, -1)

    def is_dir(self):
        """Return True if URN is directory."""
        return self._path[-1] == Urn.separate

    @staticmethod
    def normalize_path(path):
        """Normalize path."""
        result = sub("/{2,}", "/", path)
        return result if len(result) < 1 or result[-1] != Urn.separate else result[:-1]

    @staticmethod
    def compare_path(path_a, href):
        """Compare paths."""
        unqouted_path = Urn.separate + unquote(urlsplit(href).path)
        return Urn.normalize_path(path_a) == Urn.normalize_path(unqouted_path)
