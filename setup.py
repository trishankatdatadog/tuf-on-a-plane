import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="tuf-on-a-plane",
    version="0.0.1",
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
    install_requires=("securesystemslib['crypto','pynacl']>=0.17.0",),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.9",
)
