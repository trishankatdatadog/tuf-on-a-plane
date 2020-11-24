import os
from typing import cast

from .config import Config
from .exceptions import (
    RepositoryError,
    SignatureVerificationError,
)
from .models.common import (
    Filepath,
    Hashes,
    Length,
    Role,
)
from .models.metadata import Root
from .readers import (
    JSONReaderMixIn,
    ReaderMixIn,
)


# QUESTIONS
# - Who verifies metadata, and when?
# - Who reads metadata, and how?
# - Who caches metadata, and when?


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

    def __current_metadata_filename(self, rolename: Role) -> Filepath:
        return os.path.join(
            self.config.curr_metadata_cache, self.role_filename(rolename)
        )

    def __previous_metadata_filename(self, rolename: Role) -> Filepath:
        return os.path.join(
            self.config.prev_metadata_cache, self.role_filename(rolename)
        )

    def __load_root(self) -> None:
        """5.0. Load the trusted root metadata file."""
        # NOTE: we must parse the root metadata file on disk in order to get
        # the keys to verify itself in the first place.
        metadata = self.read_from_file(self.__current_metadata_filename("root"))

        # FIXME: The following line is purely to keep mypy happy; otherwise,
        # it complains that the .signed.root attribute does not exist.
        metadata.signed = cast(Root, metadata.signed)

        # Verify self-signatures on previous root metadata file.
        if not metadata.signed.root.verified(metadata.signatures, metadata.canonical):
            raise SignatureVerificationError("failed to verify self-signed root")

        # We do not support non-consistent-snapshot repositories.
        if not metadata.signed.consistent_snapshot:
            raise RepositoryError("repository does not consistent_snapshot")

        # Now that we have verified signatures, throw them away, and set the
        # current root to the actual metadata of interest.
        self.__root = metadata.signed

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

    def _download(self, path: str, length: Length, hashes: Hashes) -> Filepath:
        """Override this function to implement your own custom download logic."""
        raise NotImplementedError

    def get(self, path: str) -> Filepath:
        """Use this function to securely download and verify an update."""
        raise NotImplementedError


class JSONRepository(JSONReaderMixIn, Repository):
    """Instantiate this class to read canonical JSON TUF metadata from a
    remote repository."""

    pass
