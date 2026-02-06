from enum import Flag, auto

from pydantic import AnyUrl, ValidationError
from pydantic.dataclasses import dataclass


class ObservableType(Flag):
    CHROME_EXTENSION = auto()
    EMAIL = auto()
    FQDN = auto()
    IPV4 = auto()
    IPV6 = auto()
    MD5 = auto()
    SHA1 = auto()
    SHA256 = auto()
    URL = auto()
    BOGON = auto()

    def __add__(self, other):
        """Combine two ObservableTypes into a new ObservableType."""
        if not isinstance(other, ObservableType):
            raise TypeError(f"Cannot combine ObservableType with {type(other)}")
        return ObservableType(self.value | other.value)

    def __radd__(self, other):
        return self + other


@dataclass(slots=True)
class Observable:
    """Represents an observable value with a type and value.

    Attributes:
        type (ObservableType): The type of the observable.
        value (str): The value of the observable.

    Not yet used.
    """

    type: ObservableType
    value: str

    def __hash__(self) -> int:
        """Set membership requires the object to be hashable.
        Use a tuple of the type and value to ensure uniqueness.
        """
        return hash((self.value, self.type))

    def _return_fqdn_from_url(self) -> str:
        """Return an empty string if pydantic validation fails or if no host is present."""
        try:
            return AnyUrl(self.value).host or ""
        except ValidationError:
            return ""
