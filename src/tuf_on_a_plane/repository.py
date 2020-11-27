import os
import shutil
from typing import cast
from urllib.parse import urljoin

from .config import Config
from .download import (
    DownloaderMixIn,
    HTTPXDownloaderMixIn,
)
from .exceptions import (
    ArbitrarySoftwareAttack,
    FreezeAttack,
    NotFoundError,
    RepositoryError,
    RollbackAttack,
)
from .models.common import (
    Dir,
    Filepath,
    Role,
    Url,
    Version,
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
class Repository(DownloaderMixIn, ReaderMixIn):
    """A class to abstractly handle the TUF client application workflow for a
    single repository.

    Do not instantiate this class."""

    def __init__(self, config: Config):
        super().init_downloader()
        self.config = config
        self.__refresh()

    def close(self) -> None:
        self.config.close()
        super().close_downloader()

    def __refresh(self) -> None:
        """Refresh metadata for all top-level roles so that we have a
        consistent snapshot of the repository."""
        try:
            self.__load_root()
            self.__update_root()
            self.__update_timestamp()
            self.__update_snapshot()
            self.__update_targets()
        finally:
            self.close()

    def __local_metadata_filename(self, rolename: Role) -> Filepath:
        return os.path.join(self.config.metadata_cache, self.role_filename(rolename))

    def __load_root(self) -> None:
        """5.0. Load the trusted root metadata file."""
        # NOTE: we must parse the root metadata file on disk in order to get
        # the keys to verify itself in the first place.
        filename = self.__local_metadata_filename("root")
        metadata = self.read_from_file(filename)

        # FIXME: The following line is purely to keep mypy happy; otherwise,
        # it complains that the .signed.root attribute does not exist.
        metadata.signed = cast(Root, metadata.signed)

        # Verify self-signatures on previous root metadata file.
        if not metadata.signed.root.verified(metadata.signatures, metadata.canonical):
            raise ArbitrarySoftwareAttack(
                f"failed to verify self-signed root: {filename}"
            )

        # NOTE: the expiration of the trusted root metadata file does not
        # matter, because we will attempt to update it in the next step.

        # We do not support non-consistent-snapshot repositories.
        if not metadata.signed.consistent_snapshot:
            raise RepositoryError("repository does not consistent_snapshot")

        # Now that we have verified signatures, throw them away, and set the
        # current root to the actual metadata of interest.
        self.__root = metadata.signed

    def __remote_metadata_filename(self, rolename: Role, version: Version) -> Filepath:
        return f"{version.value}.{self.role_filename(rolename)}"

    def __remote_metadata_path(self, path: Filepath) -> Url:
        return urljoin(self.config.metadata_root, path)

    def move_file(self, src: Dir, dst: Dir) -> None:
        """Move file from <src> to <dst>."""
        shutil.move(src, dst)

    def __update_root(self) -> None:
        """5.1. Update the root metadata file."""
        counter = -1
        # 5.1.1. Let N denote the version number of the trusted root metadata file.
        n = self.__root.version

        # 5.1.8. Repeat steps 5.1.1 to 5.1.8.
        while True:
            counter += 1
            if counter > self.config.MAX_ROOT_ROTATIONS:
                break

            # 5.1.2. Try downloading version N+1 of the root metadata file.
            n += 1
            name = self.__remote_metadata_filename("root", n)
            path = self.__remote_metadata_path(name)
            try:
                tmp_file = self.download(path, self.config.MAX_ROOT_LENGTH, self.config)
            except NotFoundError:
                break
            metadata = self.read_from_file(tmp_file)
            metadata.signed = cast(Root, metadata.signed)

            # 5.1.3. Check for an arbitrary software attack.
            if not self.__root.root.verified(metadata.signatures, metadata.canonical):
                raise ArbitrarySoftwareAttack(f"{n-1} did not sign off {n} root")
            if not metadata.signed.root.verified(
                metadata.signatures, metadata.canonical
            ):
                raise ArbitrarySoftwareAttack(f"{n} root did not sign itself")

            # 5.1.4. Check for a rollback attack.
            if metadata.signed.version != n:
                raise RollbackAttack(f"{metadata.signed.version} != {n} in {path}")

            # 5.1.5. Note that the expiration of the new (intermediate) root
            # metadata file does not matter yet.

            # 5.1.6. Set the trusted root metadata file to the new root metadata file.
            self.__root = metadata.signed

        # 5.1.9. Check for a freeze attack.
        if self.__root.expires <= self.config.NOW:
            raise FreezeAttack(
                f"{self.__root.expires} <= {self.config.NOW} in {n-1} root"
            )

        # 5.1.7. Persist root metadata.
        # NOTE: We violate the spec in persisting only after checking for a
        # freeze attack, which I think is reasonable.
        self.move_file(tmp_file, self.__local_metadata_filename("root"))

        # TODO: 5.1.(10-11).

    def __update_timestamp(self) -> None:
        """5.2. Download the timestamp metadata file."""
        raise NotImplementedError

    def __update_snapshot(self) -> None:
        """5.3. Download snapshot metadata file."""
        raise NotImplementedError

    def __update_targets(self) -> None:
        """5.4. Download the top-level targets metadata file."""
        raise NotImplementedError

    def get(self, path: str) -> Filepath:
        """Use this function to securely download and verify an update."""
        raise NotImplementedError


class JSONRepository(Repository, HTTPXDownloaderMixIn, JSONReaderMixIn):
    """Instantiate this class to read canonical JSON TUF metadata from a
    remote repository."""

    pass
