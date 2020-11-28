import os
import shutil

from .models.common import Filepath


class WriterMixIn:
    """A mixin to separate details such as manipulating files."""

    def mv_file(self, src: Filepath, dst: Filepath) -> None:
        shutil.move(src, dst)

    def rm_file(self, path: Filepath, ignore_errors: bool = False) -> None:
        try:
            os.remove(path)
        except OSError:
            if not ignore_errors:
                raise
