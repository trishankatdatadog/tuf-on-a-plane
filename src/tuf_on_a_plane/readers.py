import os
from typing import Iterable

from securesystemslib.util import get_file_hashes, load_json_file

from .models.common import (
    Dir,
    Filepath,
    Hashes,
    Rolename,
)
from .models.metadata import Metadata
from .parsers.json import JSONParser


class ReaderMixIn:
    """A mixin to separate TUF metadata details such as filename extension and
    file format."""

    def cmp_file(
        self,
        path: Filepath,
        expected: Hashes,
        hash_algorithms: Iterable[str] = ("sha256", "sha512"),
    ) -> Hashes:
        observed = get_file_hashes(path, hash_algorithms=hash_algorithms)
        return observed == expected

    def file_exists(self, path: Filepath) -> bool:
        return os.path.isfile(path)

    def local_metadata_filename(
        self, metadata_cache: Dir, rolename: Rolename
    ) -> Filepath:
        return os.path.join(metadata_cache, self.role_filename(rolename))

    def role_filename(self, rolename: Rolename) -> Filepath:
        """Return the expected filename based on the rolename."""
        raise NotImplementedError

    def read_from_file(self, path: Filepath) -> Metadata:
        """Read, parse, and return the Metadata from the file."""
        raise NotImplementedError


class JSONReaderMixIn(ReaderMixIn):
    """Use this mixin to handle the JSON filename extension and file format."""

    def role_filename(self, rolename: Rolename) -> Filepath:
        """Return the expected filename based on the rolename."""
        return f"{rolename}.json"

    def read_from_file(self, path: Filepath) -> Metadata:
        """Return the expected filename based on the rolename."""
        return JSONParser.parse(load_json_file(path))
