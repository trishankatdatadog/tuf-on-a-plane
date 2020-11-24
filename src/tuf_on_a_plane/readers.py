from securesystemslib.util import load_json_file

from .models.common import (
    Filepath,
    Role,
)
from .models.metadata import Metadata
from .parsers.json import JSONParser


class ReaderMixIn:
    """A mixin to separate TUF metadata details such as filename extension and
    file format."""

    def role_filename(self, rolename: Role) -> Filepath:
        """Return the expected filename based on the rolename."""
        raise NotImplementedError

    def read_from_file(self, path: Filepath) -> Metadata:
        """Read, parse, and return the Metadata from the file."""
        raise NotImplementedError


class JSONReaderMixIn(ReaderMixIn):
    """Use this mixin to handle the JSON filename extension and file format."""

    def role_filename(self, rolename: Role) -> Filepath:
        """Return the expected filename based on the rolename."""
        return f"{rolename}.json"

    def read_from_file(self, path: Filepath) -> Metadata:
        """Return the expected filename based on the rolename."""
        # TODO: is it a big deal that we do not first check for existence of file?
        return JSONParser.parse(load_json_file(path))
