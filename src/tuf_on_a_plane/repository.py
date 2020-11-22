from dataclasses import dataclass
import os
from typing import cast

from securesystemslib.util import load_json_file

from .exceptions import SignatureVerificationError
from .models.common import (
    Dir,
    Filepath,
    Hashes,
    Length,
    Role,
    Url,
)
from .models.metadata import (
    Metadata,
    Root,
)
from .parsers.json import parse as json_parse


# QUESTIONS
# - Who verifies metadata, and when?
# - Who reads metadata, and how?
# - Who caches metadata, and when?


@dataclass
class Config:
    # Where to store the current metadata cache.
    curr_metadata_cache: Dir
    # Where to read metadata from on the remote repository.
    metadata_root: Url
    # Where to store the previous metadata cache.
    prev_metadata_cache: Dir
    # Where to store downloaded targets.
    targets_cache: Dir
    # Where to read targets from on the remote repository.
    targets_root: Url


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
        return json_parse(load_json_file(path))


# This is a Repository, not a Client, because I want to make it clear that you
# can compose these objects to traverse multiple Repositories.
class Repository(ReaderMixIn):
    """A class to abstractly handle the TUF client application workflow for a
    single repository.

    Do not instantiate this class."""

    def __init__(self, config: Config):
        self.config = config
        self.__refresh()

    def __refresh(self) -> None:
        """Refresh metadata for all top-level roles so that we have a
        consistent snapshot of the repository."""
        self.__load_root()
        self.__update_root()
        self.__update_timestamp()
        self.__update_snapshot()
        self.__update_targets()

    def __load_root(self) -> None:
        """5.0. Load the trusted root metadata file."""
        # NOTE: we must parse the root metadata file on disk in order to get
        # the keys to verify itself in the first place.
        root_filename = self.role_filename("root")
        curr_root_file = os.path.join(self.config.curr_metadata_cache, root_filename)
        curr_root = self.read_from_file(curr_root_file)
        # FIXME: The following line is purely to keep mypy happy; otherwise,
        # it complains that the .signed.root attribute does not exist.
        curr_root.signed = cast(Root, curr_root.signed)

        # Verify self-signatures on previous root metadata file.
        if not curr_root.signed.root.verify(curr_root.signatures, curr_root.canonical):
            raise SignatureVerificationError("failed to verify self-signed root")

    def __update_root(self) -> None:
        """5.1. Update the root metadata file."""
        raise NotImplementedError

    def __update_timestamp(self) -> None:
        """5.2. Download the timestamp metadata file."""
        raise NotImplementedError

    def __update_snapshot(self) -> None:
        """5.3. Download snapshot metadata file."""
        raise NotImplementedError

    def __update_targets(self) -> None:
        """5.4. Download the top-level targets metadata file."""
        raise NotImplementedError

    def download(self, path: str, length: Length, hashes: Hashes) -> Filepath:
        """Override this function to implement your own custom download logic."""
        raise NotImplementedError

    def get(self, path: str) -> Filepath:
        """Use this function to securely download and verify an update."""
        raise NotImplementedError


class JSONRepository(JSONReaderMixIn, Repository):
    """Instantiate this class to read canonical JSON TUF metadata from a
    remote repository."""

    pass
