from __future__ import annotations

from enum import Flag, auto
from functools import reduce
from operator import or_
from typing import Annotated

from pydantic import (
    AnyUrl,
    BaseModel,
    BeforeValidator,
    PlainSerializer,
    ValidationError,
    model_serializer,
)


class ObservableFlag(Flag):
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

    def __str__(self) -> str:
        return self.name or "|".join(f.name for f in ObservableFlag if f in self)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            return str(self) == other
        return super().__eq__(other)

    def __hash__(self) -> int:
        return super().__hash__()

    def __add__(self, other: ObservableFlag) -> ObservableFlag:
        """Combine two ObservableTypes into a new ObservableType."""
        if not isinstance(other, ObservableFlag):
            raise TypeError(f"Cannot combine ObservableType with {type(other)}")
        return ObservableFlag(self.value | other.value)

    def __radd__(self, other: object) -> ObservableFlag:
        return self + other

    @classmethod
    def from_str(cls, v: str | ObservableFlag) -> ObservableFlag:
        if isinstance(v, ObservableFlag):
            return v
        if isinstance(v, str):
            try:
                return reduce(or_, (cls[n.strip().upper()] for n in v.split("|")))
            except KeyError as e:
                raise ValueError(f"Invalid flag member in '{v}'") from e
        raise ValueError(f"Expected str or ObservableFlag, got {type(v)}")


"""
Create a reusable type alias for the Flag
This should help ensure serialization and deserialization both work correctly.
"""
ObservableType = Annotated[
    ObservableFlag,
    BeforeValidator(ObservableFlag.from_str),
    PlainSerializer(
        lambda v: str(v.name if v.name else "|".join(f.name for f in ObservableFlag if f in v))
    ),
]


class Observable(BaseModel):
    """Represents an observable value with a type and value.

    Attributes:
        type (ObservableType): The type of the observable.
        value (str): The value of the observable.
    """

    type: ObservableType
    value: str

    def __str__(self) -> str:
        return self.value

    def __len__(self) -> int:
        return len(self.value)

    def __getitem__(self, key: int | slice) -> str:
        return self.value[key]

    def __contains__(self, item: str) -> bool:
        return item in self.value

    def __hash__(self) -> int:
        """Set membership requires the object to be hashable.
        Use a tuple of the type and value to ensure uniqueness.
        """
        return hash((self.value, self.type))

    @model_serializer
    def __json__(self) -> dict[str, str]:
        return self.model_dump()

    def _return_fqdn_from_url(self) -> str:
        """Return an empty string if pydantic validation fails or if no host is present."""
        try:
            return AnyUrl(self.value).host or ""
        except ValidationError:
            return ""
