from pydantic import BaseModel, model_serializer


class BaseReport(BaseModel):
    success: bool
    error: str | None = None

    def __iter__(self):
        yield from self.model_dump()

    def __getitem__(self, key: str) -> object:
        return self.model_dump()[key]

    @model_serializer
    def __json__(self) -> dict[str, bool | str | None]:
        return self.model_dump()

    def get(self, name: str, default: object = None) -> object:
        return getattr(self, name, default)
