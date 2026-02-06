from dataclasses import asdict
from typing import Any

from pydantic.dataclasses import dataclass


@dataclass(slots=True)
class BaseReport:
    success: bool
    error: str | None = None

    def __iter__(self):
        yield from asdict(self)

    def __getitem__(self, key):
        return asdict(self)[key]

    def __json__(self):
        """Used for JSON serialization."""
        return asdict(self)

    def get(self, name, default: Any | None = None):
        return getattr(self, name, default)
