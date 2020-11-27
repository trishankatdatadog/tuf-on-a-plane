from typing import Any

from ..models.metadata import Metadata


class Parser:
    """Inherit this class to implement your own parser."""

    @classmethod
    def parse(cls, d: Any) -> Metadata:
        """Override this function to transform an input of any type to a
        Metadata object."""
        raise NotImplementedError
