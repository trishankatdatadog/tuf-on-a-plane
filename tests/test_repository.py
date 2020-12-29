import os
import shutil
import tempfile

from tuf_on_a_plane.models.common import Filepath
from tuf_on_a_plane.repository import Config, JSONRepository, Target


def test_e2e_succeeds():
    orig_metadata_cache = "tests/data/repository/metadata"

    temp_metadata_cache = tempfile.TemporaryDirectory()
    temp_targets_cache = tempfile.TemporaryDirectory()

    shutil.copytree(orig_metadata_cache, temp_metadata_cache.name, dirs_exist_ok=True)

    c = Config(
        "https://dd-integrations-core-wheels-build-stable.datadoghq.com/metadata.staged/",
        "https://dd-integrations-core-wheels-build-stable.datadoghq.com/targets/",
        temp_metadata_cache.name,
        temp_targets_cache.name,
    )

    def get(relpath: Filepath, depth: int = 0) -> None:
        print((depth * "\t") + relpath)
        t: Target = r.get(relpath)
        assert os.path.exists(t.path)
        if t.target.custom:
            paths = t.target.custom.get("in-toto")
            if paths:
                for path in paths:
                    get(path, depth + 1)

    try:
        r = JSONRepository(c)
    except Exception:
        temp_metadata_cache.cleanup()
        temp_targets_cache.cleanup()
        raise
    else:
        try:
            get("simple/index.html")
        finally:
            temp_metadata_cache.cleanup()
            temp_targets_cache.cleanup()
            r.close()
