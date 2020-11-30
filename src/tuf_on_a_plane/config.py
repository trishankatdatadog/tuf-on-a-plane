from dataclasses import dataclass
import shutil
import tempfile

from .models.common import (
    DateTime,
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

    # Maximum number of root rotations.
    MAX_ROOT_ROTATIONS = 2 ** 5
    # 16K ought to be more than enough for everyone ;)
    MAX_ROOT_LENGTH: Length = Length(2 ** 14)

    # Based on PEP 458:
    # https://www.python.org/dev/peps/pep-0458/#metadata-scalability
    MAX_SNAPSHOT_LENGTH: Length = Length(2 ** 17)
    MAX_TIMESTAMP_LENGTH: Length = Length(2 ** 10)

    # A fixed notion of "now" with some slack time:
    # https://github.com/theupdateframework/specification/pull/118
    NOW: DateTime = DateTime.laggingnow(minutes=5)

    # Minimum number of bytes per second that must be downloaded per second
    # *on average* to prevent raising a slow retrieval attack.
    SLOW_RETRIEVAL_THRESHOLD: Speed = Speed(2 ** 10)

    def close(self) -> None:
        shutil.rmtree(self.temp_dir)
