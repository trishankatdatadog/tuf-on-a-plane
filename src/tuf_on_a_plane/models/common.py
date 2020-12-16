from datetime import datetime, timedelta, timezone
from functools import total_ordering
import re
from typing import Any, cast, Dict, List

Dir = str
Filepath = str
Filepaths = List[Filepath]
Hashes = Dict[str, str]
Json = Dict[str, Any]
KeyID = str
Rolename = str
Url = str


class DateTime(datetime):
    @classmethod
    def laggingnow(cls, minutes: float = 0.0) -> "DateTime":
        """Return datetime.now(timezone.utc), but delayed by the
        datetime.timedelta() parameters specified."""
        return cast(DateTime, datetime.now(timezone.utc) - timedelta(minutes=minutes))

    @classmethod
    def strptime(cls, date_string: str, format: str) -> "DateTime":
        """string, format -> new datetime parsed from a string (like
        time.strptime())."""
        return cast(DateTime, super().strptime(date_string, format))


@total_ordering
class Comparable:
    def __eq__(self, other: Any) -> bool:
        raise NotImplementedError

    def __lt__(self, other: Any) -> bool:
        raise NotImplementedError


class Natural(Comparable):
    def __init__(self, value: Any):
        self.value = value

    def __add__(self, other: Any) -> Any:
        if not isinstance(other, self.__class__):
            other = self.__class__(other)
        return self.__class__(self.value + other.value)

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, self.__class__):
            other = self.__class__(other)
        return self.value == other.value

    def __lt__(self, other: Any) -> bool:
        if not isinstance(other, self.__class__):
            other = self.__class__(other)
        return self.value < other.value

    def __sub__(self, other: Any) -> Any:
        if not isinstance(other, self.__class__):
            other = self.__class__(other)
        return self.__class__(self.value - other.value)

    def __repr__(self):
        return f"{self.__class__.__name__}({self.value})"

    def __str__(self):
        return str(self.value)

    @property
    def value(self) -> int:
        return self.__value

    @value.setter
    def value(self, value: Any) -> None:
        value = round(float(value))
        if value < 0:
            raise ValueError(f"{value} < 0")
        self.__value = value


Speed = Natural


class Positive(Natural):
    # FIXME: This is actually implicitly defined by @total_ordering, but mypy
    # does not pick it up: https://github.com/python/mypy/issues/4610
    def __le__(self, other: Any) -> bool:
        if not isinstance(other, self.__class__):
            other = self.__class__(other)
        return self.value <= other.value

    @property
    def value(self) -> int:
        return self.__value

    @value.setter
    def value(self, value: Any) -> None:
        value = round(float(value))
        if value <= 0:
            raise ValueError(f"{value} <= 0")
        self.__value = value


Length = Positive
Threshold = Positive


class Version(Positive):
    def __str__(self):
        return f"v{self.value}"


class SpecVersion:
    # https://semver.org/#is-there-a-suggested-regular-expression-regex-to-check-a-semver-string
    SemVer = r"^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"

    def __init__(self, value: str) -> None:
        m = re.match(self.SemVer, value)
        if m is None:
            raise ValueError(f"{value} is not a SemVer")
        else:
            self.__value = value
            self.__major = Natural(m.group("major"))
            self.__minor = Natural(m.group("minor"))
            self.__patch = Natural(m.group("patch"))
            self.__prerelease = m.group("prerelease")
            self.__buildmetadata = m.group("buildmetadata")

    def __repr__(self):
        return f"{self.__class__.__name__}({self.value})"

    def __str__(self):
        return f"v{self.value}"

    @property
    def major(self) -> Natural:
        return self.__major

    @property
    def minor(self) -> Natural:
        return self.__minor

    @property
    def patch(self) -> Natural:
        return self.__patch

    @property
    def value(self) -> str:
        return self.__value
