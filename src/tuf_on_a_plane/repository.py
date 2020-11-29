from typing import cast
from urllib.parse import urljoin

from .config import Config
from .download import DownloaderMixIn, HTTPXDownloaderMixIn
from .exceptions import (
    ArbitrarySoftwareAttack,
    FreezeAttack,
    NoConsistentSnapshotsError,
    NotFoundError,
    RollbackAttack,
)
from .models.common import (
    Filepath,
    Rolename,
    Url,
    Version,
)
from .models.metadata import (
    Metadata,
    Root,
    Signed,
    ThresholdOfPublicKeys,
    TimeSnap,
    Timestamp,
)
from .readers import JSONReaderMixIn, ReaderMixIn
from .writers import WriterMixIn


# This is a Repository, not a Client, because I want to make it clear that you
# can compose these objects to traverse multiple Repositories.
class Repository(WriterMixIn, DownloaderMixIn, ReaderMixIn):
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

    def __check_expiry(self, signed: Signed) -> None:
        if signed.expires <= self.config.NOW:
            raise FreezeAttack(f"{signed}: {signed.expires} <= {self.config.NOW}")

    # FIXME: maybe we can write a Comparable interface, but I'm too tired right
    # now: https://github.com/python/typing/issues/59
    def __check_rollback(self, prev: Signed, curr: Signed) -> None:
        if prev > curr:
            raise RollbackAttack(f"{prev} > {curr}")

    def __check_signatures(
        self, role: ThresholdOfPublicKeys, metadata: Metadata
    ) -> None:
        if not role.verified(metadata.signatures, metadata.canonical):
            raise ArbitrarySoftwareAttack(f"{metadata.signed}")

    def __local_metadata_filename(self, rolename: Rolename) -> Filepath:
        return self.local_metadata_filename(self.config.metadata_cache, rolename)

    def __remote_metadata_filename(
        self, rolename: Rolename, version: Version
    ) -> Filepath:
        return f"{version.value}.{self.role_filename(rolename)}"

    def __remote_metadata_path(self, path: Filepath) -> Url:
        return urljoin(self.config.metadata_root, path)

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
        self.__check_signatures(metadata.signed.root, metadata)

        # NOTE: the expiration of the trusted root metadata file does not
        # matter, because we will attempt to update it in the next step.

        # We do not support non-consistent-snapshot repositories.
        if not metadata.signed.consistent_snapshot:
            raise NoConsistentSnapshotsError

        # Now that we have verified signatures, throw them away, and set the
        # current root to the actual metadata of interest.
        self.__root = metadata.signed

    def __update_root(self) -> None:
        """5.1. Update the root metadata file."""
        # 5.1.1. Let N denote the version number of the trusted root metadata
        # file.
        curr_root = self.__root
        n = curr_root.version

        # 5.1.8. Repeat steps 5.1.1 to 5.1.8.
        for _ in range(self.config.MAX_ROOT_ROTATIONS):
            # 5.1.2. Try downloading version N+1 of the root metadata file.
            n += 1
            name = self.__remote_metadata_filename("root", n)
            path = self.__remote_metadata_path(name)
            try:
                tmp_file = self.download(path, self.config.MAX_ROOT_LENGTH, self.config)
            except NotFoundError:
                break

            # 5.1.3. Check for an arbitrary software attack.
            metadata = self.read_from_file(tmp_file)
            metadata.signed = cast(Root, metadata.signed)
            self.__check_signatures(curr_root.root, metadata)
            self.__check_signatures(metadata.signed.root, metadata)

            # 5.1.4. Check for a rollback attack.
            if metadata.signed.version != n:
                raise RollbackAttack(f"{metadata.signed.version} != {n} in {path}")

            # 5.1.5. Note that the expiration of the new (intermediate) root
            # metadata file does not matter yet.

            # 5.1.6. Set the trusted root metadata file to the new root metadata
            # file.
            curr_root = metadata.signed

        # 5.1.11. Set whether consistent snapshots are used as per the trusted
        # root metadata file (see Section 4.3).
        # NOTE: We violate the spec in checking this *before* deleting local
        # timestamp and/or snapshot metadata, which I think is reasonable.
        if not curr_root.consistent_snapshot:
            raise NoConsistentSnapshotsError

        # 5.1.9. Check for a freeze attack.
        self.__check_expiry(curr_root)

        # 5.1.10. If the timestamp and / or snapshot keys have been rotated,
        # then delete the trusted timestamp and snapshot metadata files.
        if (
            self.__root.timestamp != curr_root.timestamp
            or self.__root.snapshot != curr_root.snapshot
        ):
            self.rm_file(self.__local_metadata_filename("snapshot"), ignore_errors=True)
            self.rm_file(
                self.__local_metadata_filename("timestamp"), ignore_errors=True
            )

        # 5.1.7. Persist root metadata.
        # NOTE: We violate the spec in persisting only *after* checking
        # everything, which I think is reasonable.
        self.mv_file(tmp_file, self.__local_metadata_filename("root"))
        self.__root = curr_root

    def __update_timestamp(self) -> None:
        """5.2. Download the timestamp metadata file."""
        name = self.role_filename("timestamp")
        path = self.__remote_metadata_path(name)
        tmp_file = self.download(path, self.config.MAX_TIMESTAMP_LENGTH, self.config)

        # 5.2.1. Check for an arbitrary software attack.
        curr_metadata = self.read_from_file(tmp_file)
        curr_metadata.signed = cast(Timestamp, curr_metadata.signed)
        curr_metadata.signed.snapshot = cast(TimeSnap, curr_metadata.signed.snapshot)
        self.__check_signatures(self.__root.timestamp, curr_metadata)

        # 5.2.2. Check for a rollback attack.
        prev_filename = self.__local_metadata_filename("timestamp")
        if self.file_exists(prev_filename):
            prev_metadata = self.read_from_file(prev_filename)
            prev_metadata.signed = cast(Timestamp, prev_metadata.signed)
            prev_metadata.signed.snapshot = cast(
                TimeSnap, prev_metadata.signed.snapshot
            )
            self.__check_rollback(prev_metadata.signed, curr_metadata.signed)

            # FIXME: ideally, self.__check_rollback() takes Comparable so that
            # we can reuse it.
            if prev_metadata.signed.snapshot > curr_metadata.signed.snapshot:
                raise RollbackAttack(
                    f"{prev_metadata.signed.snapshot} > {curr_metadata.signed.snapshot}"
                )

        # 5.2.3. Check for a freeze attack.
        self.__check_expiry(curr_metadata.signed)

        # 5.2.4. Persist timestamp metadata.
        self.mv_file(tmp_file, self.__local_metadata_filename("timestamp"))
        self.__timestamp = curr_metadata.signed

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
