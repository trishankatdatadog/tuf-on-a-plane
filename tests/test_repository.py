import os
import shutil
import tempfile

from tuf_on_a_plane.repository import Config, JSONRepository


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

    try:
        r = JSONRepository(c)
    except Exception:
        temp_metadata_cache.cleanup()
        temp_targets_cache.cleanup()
    else:
        try:
            # Exists in the top-level targets role.
            f = r.get("in-toto-metadata/root.layout")
            assert os.path.exists(f)

            # Exists in delegated targets role.
            f = r.get("simple/index.html")
            assert os.path.exists(f)
        finally:
            temp_metadata_cache.cleanup()
            temp_targets_cache.cleanup()
            r.close()
