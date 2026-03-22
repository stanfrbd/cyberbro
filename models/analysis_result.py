import json

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Text
from sqlalchemy.types import TypeDecorator

from models.observable import Observable, ObservableFlag

db = SQLAlchemy()


class JSONEncodedResults(TypeDecorator):
    """Serializes list[Results] to/from JSON text in SQLite.

    On write: Observable -> {"__observable__": {"value": ..., "type": ...}}
              ObservableFlag -> {"__flag__": "IPV4"}
    On read:  Reconstructs Observable and ObservableFlag from tagged dicts.
    """

    impl = Text
    cache_ok = True

    def process_bind_param(self, value: list[dict] | None, dialect: object) -> str | None:
        if value is None:
            return None
        return json.dumps(value, default=self._json_default)

    def process_result_value(self, value: str | None, dialect: object) -> list[dict] | None:
        if value is None:
            return None
        raw = json.loads(value)
        return [self._reconstruct(item) for item in raw if item is not None]

    @staticmethod
    def _json_default(obj: object) -> dict[str, str | dict[str, str]]:
        if isinstance(obj, Observable):
            return {"__observable__": {"value": obj.value, "type": str(obj.type)}}
        if isinstance(obj, ObservableFlag):
            return {"__flag__": str(obj)}
        raise TypeError(f"Not JSON serializable: {type(obj)}")

    @staticmethod
    def _reconstruct(item: object) -> object:
        """Reconstruct Observable/ObservableFlag from stored JSON."""
        if not isinstance(item, dict):
            return item

        # Handle 'observable' field
        obs = item.get("observable")
        if isinstance(obs, dict) and "__observable__" in obs:
            data = obs["__observable__"]
            item["observable"] = Observable(value=data["value"], type=data["type"])
        elif isinstance(obs, str):
            # Legacy data: observable was a plain string, type was separate
            type_raw = item.get("type", "FQDN")
            type_str = type_raw if isinstance(type_raw, str) else str(type_raw)
            item["observable"] = Observable(value=obs, type=type_str)

        # Handle 'type' field
        type_val = item.get("type")
        if isinstance(type_val, dict) and "__flag__" in type_val:
            item["type"] = ObservableFlag.from_str(type_val["__flag__"])
        elif isinstance(type_val, str):
            # Legacy or serialized string like "IPV4" or "IPv4"
            item["type"] = ObservableFlag.from_str(type_val)

        return item


class AnalysisResult(db.Model):
    id = db.Column(db.String, primary_key=True)
    results = db.Column(JSONEncodedResults, nullable=False)
    start_time = db.Column(db.Float, nullable=False)
    end_time = db.Column(db.Float, nullable=True)
    start_time_string = db.Column(db.String, nullable=False)
    end_time_string = db.Column(db.String, nullable=True)
    analysis_duration_string = db.Column(db.String, nullable=True)
    analysis_duration = db.Column(db.Float, nullable=True)
    selected_engines = db.Column(db.JSON, nullable=False)
    in_progress = db.Column(db.Boolean, default=True)
