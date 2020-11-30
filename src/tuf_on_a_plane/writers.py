import os
import shutil

from .models.common import Filepath


class WriterMixIn:
    """A mixin to separate details such as manipulating files."""

    def mv_file(self, src: Filepath, dst: Filepath) -> None:
        dst_dir = os.path.dirname(dst)
        if not os.path.isdir(dst_dir):
            os.makedirs(dst_dir, mode=0o700, exist_ok=True)
        shutil.move(src, dst)

    def rm_file(self, path: Filepath, ignore_errors: bool = False) -> None:
        try:
            os.remove(path)
        except OSError:
            if not ignore_errors:
                raise
