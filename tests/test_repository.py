import shutil
import tempfile

from tuf_on_a_plane.repository import Config, JSONRepository


def test_main_succeeds():
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
        JSONRepository(c)
    except NotImplementedError:
        raise
    finally:
        temp_metadata_cache.cleanup()
        temp_targets_cache.cleanup()
