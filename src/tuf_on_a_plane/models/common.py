import re
from typing import Any, Dict

Dir = str
Filepath = str
Hashes = Dict[str, str]
Json = Dict[str, Any]
KeyID = str
Role = str
Url = str


class Positive(int):
    def __init__(self, value: int):
        if value <= 0:
            raise ValueError(f"{value} <= 0")
        self.value = value

    def __repr__(self):
        return f"Positive({self.value})"

    def __str__(self):
        return str(self.value)


Length = Positive
Threshold = Positive
Version = Positive


class SpecVersion:
    # https://semver.org/#is-there-a-suggested-regular-expression-regex-to-check-a-semver-string
    SemVer = r"^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"

    def __init__(self, value: str) -> None:
        m = re.match(self.SemVer, value)
        if m is None:
            raise ValueError(f"{value} is not a SemVer")
        else:
            self.value = value
            self.major = int(m.group("major"))
            self.minor = int(m.group("minor"))
            self.patch = int(m.group("patch"))
            self.prerelease = m.group("prerelease")
            self.buildmetadata = m.group("buildmetadata")

    def __repr__(self):
        return f"SpecVersion({self.value})"

    def __str__(self):
        return self.value


RoleToHashes = Dict[Role, Hashes]
RoleToVersion = Dict[Role, Version]
