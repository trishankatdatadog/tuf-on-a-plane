from dataclasses import dataclass
import os
import shutil
import tempfile

from .models.common import (
    DateTime,
    Dir,
    Length,
    Positive,
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

    # Maximum number of unique targets roles to visit per target.
    MAX_PREORDER_DFS_VISITS = Positive(2 ** 5)

    # Maximum number of root rotations.
    MAX_ROOT_ROTATIONS = 2 ** 5
    MAX_ROOT_LENGTH: Length = Length(2 ** 15)

    # Based on PEP 458:
    # https://www.python.org/dev/peps/pep-0458/#metadata-scalability
    MAX_SNAPSHOT_LENGTH: Length = Length(2 ** 17)
    MAX_TARGETS_LENGTH: Length = Length(2 ** 21)
    MAX_TIMESTAMP_LENGTH: Length = Length(2 ** 11)

    # A fixed notion of "now" with some slack time:
    # https://github.com/theupdateframework/specification/pull/118
    NOW: DateTime = DateTime.laggingnow(minutes=5)

    # Minimum number of bytes per second that must be downloaded per second
    # *per chunk* to prevent raising a slow retrieval attack.
    SLOW_RETRIEVAL_THRESHOLD: Speed = Speed(2 ** 13)

    def close(self) -> None:
        if os.path.isdir(self.temp_dir):
            shutil.rmtree(self.temp_dir)
