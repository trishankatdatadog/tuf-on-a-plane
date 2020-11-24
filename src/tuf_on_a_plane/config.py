from dataclasses import dataclass

from .models.common import (
    Dir,
    Url,
)


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
