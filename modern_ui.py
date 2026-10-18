"""Optional compiled Vue interface; the classic interface remains available."""

import json
from pathlib import Path

from flask import Blueprint, current_app, render_template
from pydantic import BaseModel, Field, ValidationError


class FrontendConfig(BaseModel):
    api_prefix: str = Field(serialization_alias="apiPrefix")
    engines: list[str]
    enabled_engines: list[str] = Field(serialization_alias="enabledEngines")


class BuildAsset(BaseModel):
    file: str
    css: list[str] = Field(default_factory=list)


def create_ui_blueprint(
    api_prefix: str, engine_names: list[str], enabled_engines: list[str]
) -> Blueprint:
    """Create the UI without exposing engine credentials to the browser."""
    blueprint: Blueprint = Blueprint("modern_ui", __name__)
    config: FrontendConfig = FrontendConfig(
        api_prefix=api_prefix, engines=engine_names, enabled_engines=enabled_engines
    )

    @blueprint.get("/ui")
    def modern_ui() -> tuple[str, int]:
        static_dir: str | None = current_app.static_folder
        if static_dir is None:
            return "Frontend static directory is not configured.", 503
        manifest_path: Path = Path(static_dir) / "ui" / ".vite" / "manifest.json"
        try:
            manifest: dict[str, object] = json.loads(manifest_path.read_text())
            asset: BuildAsset = BuildAsset.model_validate(manifest["index.html"])
        except (OSError, ValueError, KeyError, TypeError, ValidationError):
            return "Frontend not built. Run npm ci && npm run build in frontend/.", 503
        return render_template(
            "modern_ui.html",
            frontend_config=config.model_dump(by_alias=True),
            frontend_script=asset.file,
            frontend_styles=asset.css,
        ), 200

    return blueprint
