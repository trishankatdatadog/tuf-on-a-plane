from dataclasses import dataclass
import shutil
import tempfile

from .models.common import (
    Dir,
    Length,
    Speed,
    Url,
)


@dataclass
class Config:
    # Where to read metadata from on the remote repository.
    metadata_root: Url
    # Where to read targets from on the remote repository.
    targets_root: Url
    # Where to store downloaded metadata.
    metadata_cache: Dir
    # Where to store downloaded targets.
    targets_cache: Dir

    # Where to store temporary files.
    temp_dir = tempfile.mkdtemp()

    # Maximum number of root rotations. If you consider once per year, ten
    # years should be more than enough.
    MAX_ROOT_ROTATIONS = 10
    # 16K ought to be more than enough for everyone ;)
    MAX_ROOT_LENGTH: Length = Length(2 ** 14)

    # Minimum number of bytes that must be downloaded per second *on average*
    # to prevent raising a slow retrieval attack. 1KB/s seems reasonable.
    MIN_BYTES_PER_SEC: Speed = Speed(2 ** 10)

    def close(self) -> None:
        shutil.rmtree(self.temp_dir)
