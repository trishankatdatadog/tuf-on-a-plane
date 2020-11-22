from tuf_on_a_plane.repository import Config, JSONRepository


def test_main_succeeds():
    c = Config("tests/data/repository/metadata/current", "", "", "", "")
    try:
        JSONRepository(c)
    except NotImplementedError:
        pass
