from dataclasses import dataclass
from fnmatch import fnmatch
from typing import cast, Optional
from urllib.parse import urljoin

from .config import Config
from .download import DownloaderMixIn, HTTPXDownloaderMixIn
from .exceptions import (
    ArbitrarySoftwareAttack,
    DownloadNotFoundError,
    EndlessDataAttack,
    FreezeAttack,
    InconsistentTargetError,
    MixAndMatchAttack,
    NoConsistentSnapshotsError,
    RollbackAttack,
    TargetNotFoundError,
)
from .models.common import (
    Comparable,
    Filepath,
    Hash,
    Hashes,
    Length,
    Positive,
    Rolename,
    Rolenames,
    Url,
    Version,
)
from .models.metadata import (
    Metadata,
    Root,
    Signed,
    Snapshot,
    TargetFile,
    Targets,
    ThresholdOfPublicKeys,
    TimeSnap,
    Timestamp,
)
from .readers import JSONReaderMixIn, ReaderMixIn
from .writers import WriterMixIn


@dataclass
class Target:
    path: Filepath
    target: TargetFile


# This is a Repository, not a Client, because I want to make it clear that you
# can compose these objects to traverse multiple Repositories.
class Repository(WriterMixIn, DownloaderMixIn, ReaderMixIn):
    """A class to abstractly handle the TUF client application workflow for a
    single repository.

    Do not instantiate this class."""

    ROOT_ROLENAME = "root"
    SNAPSHOT_ROLENAME = "snapshot"
    TARGETS_ROLENAME = "targets"
    TIMESTAMP_ROLENAME = "timestamp"

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

    def __check_hashes(self, abspath: Filepath, expected: Optional[Hashes]) -> None:
        if expected and not self.check_hashes(abspath, expected):
            raise ArbitrarySoftwareAttack(f"{abspath} != {expected}")

    def __check_length(self, abspath: Filepath, expected: Length) -> None:
        if not self.check_length(abspath, expected):
            raise EndlessDataAttack(f"{abspath} > {expected} bytes")

    def __check_rollback(self, prev: Comparable, curr: Comparable) -> None:
        if prev > curr:
            raise RollbackAttack(f"{prev} > {curr}")

    def __check_signatures(
        self, role: ThresholdOfPublicKeys, metadata: Metadata
    ) -> None:
        if not role.verified(metadata.signatures, metadata.canonical):
            raise ArbitrarySoftwareAttack(f"{metadata.signed}")

    def __check_version(self, signed: Signed, timesnap: TimeSnap) -> None:
        if signed.version != timesnap.version:
            raise MixAndMatchAttack(f"{signed.version} != {timesnap.version}")

    def __local_metadata_filename(self, rolename: Rolename) -> Filepath:
        return self.join_path(self.config.metadata_cache, self.role_filename(rolename))

    def __local_targets_filename(self, relpath: Filepath) -> Filepath:
        return self.join_path(self.config.targets_cache, relpath)

    def __remote_metadata_filename(
        self, rolename: Rolename, version: Version
    ) -> Filepath:
        return f"{version.value}.{self.role_filename(rolename)}"

    def __remote_metadata_path(self, relpath: Filepath) -> Url:
        return urljoin(self.config.metadata_root, relpath)

    def __remote_targets_path(self, relpath: Filepath, _hash: Hash) -> Url:
        dirname, basename = self.split_path(relpath)
        basename = f"{_hash}.{basename}"
        relpath = self.join_path(dirname, basename)
        return urljoin(self.config.targets_root, relpath)

    def __refresh(self) -> None:
        """Refresh metadata for root, timestamp, and snapshot so that we have a
        consistent snapshot of the repository."""
        try:
            self.__load_root()
            self.__update_root()
            self.__update_timestamp()
            self.__update_snapshot()
        except Exception:
            self.close()
            raise

    def __load_root(self) -> None:
        """5.1. Load the trusted root metadata file."""
        # NOTE: we must parse the root metadata file on disk in order to get
        # the keys to verify itself in the first place.
        filename = self.__local_metadata_filename(self.ROOT_ROLENAME)
        metadata = self.read_from_file(filename)

        # FIXME: the following line is purely to keep mypy happy; otherwise,
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
        """5.2. Update the root metadata file."""
        # 5.2.1. Let N denote the version number of the trusted root metadata
        # file.
        prev_root = self.__root
        curr_root = prev_root
        n = curr_root.version

        # 5.2.8. Repeat steps 5.2.1 to 5.2.8.
        for _ in range(self.config.MAX_ROOT_ROTATIONS):
            # 5.2.2. Try downloading version N+1 of the root metadata file.
            n += 1
            remote_filename = self.__remote_metadata_filename(self.ROOT_ROLENAME, n)
            remote_path = self.__remote_metadata_path(remote_filename)
            try:
                tmp_file = self.download(
                    remote_path, self.config.MAX_ROOT_LENGTH, self.config
                )
            except DownloadNotFoundError:
                break
            self.__check_length(tmp_file, self.config.MAX_ROOT_LENGTH)

            # 5.2.3. Check for an arbitrary software attack.
            metadata = self.read_from_file(tmp_file)
            metadata.signed = cast(Root, metadata.signed)
            self.__check_signatures(curr_root.root, metadata)
            self.__check_signatures(metadata.signed.root, metadata)

            # 5.2.4. Check for a rollback attack.
            if metadata.signed.version != n:
                raise RollbackAttack(
                    f"{metadata.signed.version} != {n} in {remote_path}"
                )

            # 5.2.5. Note that the expiration of the new (intermediate) root
            # metadata file does not matter yet.

            # 5.2.6. Set the trusted root metadata file to the new root metadata
            # file.
            curr_root = metadata.signed

        # 5.2.9. Check for a freeze attack.
        self.__check_expiry(curr_root)

        if prev_root < curr_root:
            # 5.2.11. Set whether consistent snapshots are used as per the
            # trusted root metadata file.
            # NOTE: We violate the spec in checking this *before* deleting local
            # timestamp and/or snapshot metadata, which I think is reasonable.
            if not curr_root.consistent_snapshot:
                raise NoConsistentSnapshotsError

            # 5.2.10. If the timestamp and / or snapshot keys have been rotated,
            # then delete the trusted timestamp and snapshot metadata files.
            if (
                self.__root.timestamp != curr_root.timestamp
                or self.__root.snapshot != curr_root.snapshot
            ):
                filename = self.__local_metadata_filename(self.SNAPSHOT_ROLENAME)
                if self.file_exists(filename):
                    self.rm_file(filename)

                filename = self.__local_metadata_filename(self.TIMESTAMP_ROLENAME)
                if self.file_exists(filename):
                    self.rm_file(filename)

            # 5.2.7. Persist root metadata.
            # NOTE: We violate the spec in persisting only *after* checking
            # everything, which I think is reasonable.
            self.mv_file(tmp_file, self.__local_metadata_filename(self.ROOT_ROLENAME))
            self.__root = curr_root

    def __get_prev_metadata(self, rolename: Rolename) -> Optional[Metadata]:
        filename = self.__local_metadata_filename(rolename)
        if self.file_exists(filename):
            return self.read_from_file(filename)
        return None

    def __update_timestamp(self) -> None:
        """5.3. Download the timestamp metadata file."""
        role_filename = self.role_filename(self.TIMESTAMP_ROLENAME)
        remote_path = self.__remote_metadata_path(role_filename)
        tmp_file = self.download(
            remote_path, self.config.MAX_TIMESTAMP_LENGTH, self.config
        )
        self.__check_length(tmp_file, self.config.MAX_TIMESTAMP_LENGTH)

        # 5.3.1. Check for an arbitrary software attack.
        curr_metadata = self.read_from_file(tmp_file)
        curr_metadata.signed = cast(Timestamp, curr_metadata.signed)
        self.__check_signatures(self.__root.timestamp, curr_metadata)

        # 5.3.2. Check for a rollback attack.
        prev_metadata = self.__get_prev_metadata(self.TIMESTAMP_ROLENAME)
        if prev_metadata:
            prev_metadata.signed = cast(Timestamp, prev_metadata.signed)
            self.__check_rollback(prev_metadata.signed, curr_metadata.signed)
            self.__check_rollback(
                prev_metadata.signed.snapshot, curr_metadata.signed.snapshot
            )

        # 5.3.3. Check for a freeze attack.
        self.__check_expiry(curr_metadata.signed)

        # 5.3.4. Persist timestamp metadata.
        self.mv_file(tmp_file, self.__local_metadata_filename(self.TIMESTAMP_ROLENAME))
        self.__timestamp = curr_metadata.signed

    def __update_snapshot(self) -> None:
        """5.4. Download snapshot metadata file."""
        prev_metadata = self.__get_prev_metadata(self.SNAPSHOT_ROLENAME)
        obsolete = (
            not prev_metadata
            or prev_metadata.signed.version < self.__timestamp.snapshot.version
        )
        local_filename = self.__local_metadata_filename(self.SNAPSHOT_ROLENAME)
        length = self.__timestamp.snapshot.length or self.config.MAX_SNAPSHOT_LENGTH

        # Download metadata only if not cached or if it is obsolete.
        if not obsolete:
            tmp_file = local_filename
        else:
            remote_filename = self.__remote_metadata_filename(
                self.SNAPSHOT_ROLENAME, self.__timestamp.snapshot.version
            )
            remote_path = self.__remote_metadata_path(remote_filename)
            tmp_file = self.download(remote_path, length, self.config)

        self.__check_length(tmp_file, length)

        # 5.4.1. Check against timestamp role's snapshot hash.
        self.__check_hashes(tmp_file, self.__timestamp.snapshot.hashes)

        # 5.4.2. Check for an arbitrary software attack.
        curr_metadata = self.read_from_file(tmp_file)
        curr_metadata.signed = cast(Snapshot, curr_metadata.signed)
        self.__check_signatures(self.__root.snapshot, curr_metadata)

        # 5.4.3. Check against timestamp role's snapshot version.
        self.__check_version(curr_metadata.signed, self.__timestamp.snapshot)

        # 5.4.4. Check for a rollback attack.
        if prev_metadata:
            prev_metadata.signed = cast(Snapshot, prev_metadata.signed)

            for filename, prev_timesnap in prev_metadata.signed.targets.items():
                curr_timesnap = curr_metadata.signed.targets.get(filename)
                if not curr_timesnap:
                    raise RollbackAttack(
                        f"{filename} was in {prev_metadata.signed.version} but missing in {curr_metadata.signed.version}"
                    )
                self.__check_rollback(prev_timesnap, curr_timesnap)

        # 5.4.5. Check for a freeze attack.
        self.__check_expiry(curr_metadata.signed)

        # 5.4.6. Persist snapshot metadata.
        if obsolete:
            self.mv_file(tmp_file, local_filename)
        self.__snapshot = curr_metadata.signed

    def __preorder_dfs(
        self,
        targets: Targets,
        target_relpath: Filepath,
        visited: Rolenames,
        counter: Positive,
    ) -> Optional[TargetFile]:
        target_file = targets.targets.get(target_relpath)
        if target_file:
            return target_file
        else:
            for rolename, delegation in targets.delegations.items():
                if rolename not in visited:
                    for path in delegation.paths:
                        if fnmatch(target_relpath, path):
                            target_file = self.__update_targets(
                                visited,
                                counter + 1,
                                rolename,
                                delegation.role,
                                target_relpath,
                            )
                            if target_file or delegation.terminating:
                                return target_file
            return None

    def __update_targets(
        self,
        visited: Rolenames,
        counter: Positive,
        rolename: Rolename,
        role: ThresholdOfPublicKeys,
        target_relpath: Filepath,
    ) -> Optional[TargetFile]:
        """5.5. Download the top-level targets metadata file."""
        if rolename in visited or counter > self.config.MAX_PREORDER_DFS_VISITS:
            return None
        visited.add(rolename)

        role_filename = self.role_filename(rolename)
        timesnap = self.__snapshot.targets.get(role_filename)
        if not timesnap:
            raise MixAndMatchAttack(f"{rolename} not in {self.__snapshot}")

        prev_metadata = self.__get_prev_metadata(rolename)
        obsolete = not prev_metadata or prev_metadata.signed.version < timesnap.version
        local_filename = self.__local_metadata_filename(rolename)
        length = timesnap.length or self.config.MAX_TARGETS_LENGTH

        # Download metadata only if not cached or if it is obsolete.
        if not obsolete:
            tmp_file = local_filename
        else:
            remote_filename = self.__remote_metadata_filename(
                rolename, timesnap.version
            )
            remote_path = self.__remote_metadata_path(remote_filename)
            tmp_file = self.download(remote_path, length, self.config)

        self.__check_length(tmp_file, length)

        # 5.5.1. Check against snapshot role's targets hash.
        self.__check_hashes(tmp_file, timesnap.hashes)

        # 5.5.2. Check for an arbitrary software attack.
        curr_metadata = self.read_from_file(tmp_file)
        curr_metadata.signed = cast(Targets, curr_metadata.signed)
        self.__check_signatures(role, curr_metadata)

        # 5.5.3. Check against snapshot role's targets version.
        self.__check_version(curr_metadata.signed, timesnap)

        # 5.5.4. Check for a freeze attack.
        self.__check_expiry(curr_metadata.signed)

        # 5.5.5. Persist targets metadata.
        if obsolete:
            self.mv_file(tmp_file, local_filename)

        # 5.5.6. Perform a pre-order depth-first search for metadata about the
        # desired target, beginning with the top-level targets role.
        return self.__preorder_dfs(
            curr_metadata.signed, target_relpath, visited, counter
        )

    def __get_target(self, target_file: TargetFile, relpath: Filepath) -> Filepath:
        # Try downloading every consistent snapshot of the target until we get a
        # hit.
        for _hash in target_file.hashes.values():
            remote_path = self.__remote_targets_path(relpath, _hash)
            try:
                return self.download(remote_path, target_file.length, self.config)
            except DownloadNotFoundError:
                continue
            else:
                break
        else:
            raise InconsistentTargetError(f"{relpath}")

    # FIXME: consider using a context manager for cleanup.
    def get(self, relpath: Filepath) -> Target:
        """Use this function to securely download and verify an update."""
        try:
            # 5.6. Verify the desired target against its targets metadata.
            target_file = self.__update_targets(
                set(), Positive(1), self.TARGETS_ROLENAME, self.__root.targets, relpath
            )

            # 5.6.2. Otherwise (if there is targets metadata about this target),
            # download the target, and verify that its hashes match the targets
            # metadata.
            if target_file:
                local_path = self.__local_targets_filename(relpath)
                file_exists = self.file_exists(local_path)

                # Download target only if not cached.
                if file_exists:
                    tmp_file = local_path
                else:
                    tmp_file = self.__get_target(target_file, relpath)

                self.__check_length(tmp_file, target_file.length)
                self.__check_hashes(tmp_file, target_file.hashes)

                if not file_exists:
                    self.mv_file(tmp_file, local_path)
                return Target(local_path, target_file)

        except Exception as e:
            self.close()
            raise TargetNotFoundError(f"{relpath}") from e

        else:
            # 5.6.1. If there is no targets metadata about this target, abort
            # the update cycle and report that there is no such target.
            self.close()
            raise TargetNotFoundError(f"{relpath}")


class JSONRepository(Repository, HTTPXDownloaderMixIn, JSONReaderMixIn):
    """Instantiate this class to read canonical JSON TUF metadata from a
    remote repository."""

    pass
