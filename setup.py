import codecs
import os

import setuptools


def read(rel_path):
    here = os.path.abspath(os.path.dirname(__file__))
    # intentionally *not* adding an encoding option to open, See:
    #   https://github.com/pypa/virtualenv/issues/201#issuecomment-3145690
    with codecs.open(os.path.join(here, rel_path), "r") as fp:
        return fp.read()


def get_version(rel_path):
    for line in read(rel_path).splitlines():
        if line.startswith("__version__"):
            # __version__ = "0.9"
            delim = '"' if '"' in line else "'"
            return line.split(delim)[1]
    raise RuntimeError("Unable to find version string.")


with open("README.md", "r") as fh:
    long_description = fh.read()


setuptools.setup(
    name="tuf-on-a-plane",
    version=get_version("src/tuf_on_a_plane/__init__.py"),
    author="Trishank Karthik Kuppusamy",
    author_email="trishank.kuppusamy@datadoghq.com",
    description="A minimal, Pythonic TUF client",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/trishankatdatadog/tuf-on-a-plane",
    packages=setuptools.find_packages(
        exclude=(
            "docs",
            "scripts",
            "tests",
        )
    ),
    # TODO: Consider vendoring as much as possible.
    install_requires=(
        "httpx[http2]",
        "securesystemslib[crypto,pynacl]",
    ),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.9",
)
