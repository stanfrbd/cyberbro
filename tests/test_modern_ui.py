"""The optional UI serves built assets without exposing application secrets."""

import json
from pathlib import Path

import pytest
from flask import Flask
from flask.testing import FlaskClient

from modern_ui import create_ui_blueprint


@pytest.fixture
def client(tmp_path: Path) -> FlaskClient:
    template_dir: Path = Path(__file__).resolve().parents[1] / "templates"
    app: Flask = Flask(
        __name__,
        static_folder=str(tmp_path),
        template_folder=str(template_dir),
        static_url_path="/static",
    )
    app.register_blueprint(create_ui_blueprint("custom/api", ["reverse_dns"], ["reverse_dns"]))
    app.config["TESTING"] = True
    return app.test_client()


@pytest.mark.parametrize("manifest_content", [None, "invalid", "{}", '{"index.html": null}'])
def test_missing_or_invalid_build(
    client: FlaskClient, tmp_path: Path, manifest_content: str | None
) -> None:
    if manifest_content is not None:
        manifest_dir: Path = tmp_path / "ui" / ".vite"
        manifest_dir.mkdir(parents=True)
        (manifest_dir / "manifest.json").write_text(manifest_content)
    response = client.get("/ui")
    assert response.status_code == 503
    assert b"Frontend not built" in response.data


def test_compiled_assets_and_custom_configuration(client: FlaskClient, tmp_path: Path) -> None:
    manifest_dir: Path = tmp_path / "ui" / ".vite"
    manifest_dir.mkdir(parents=True)
    (manifest_dir / "manifest.json").write_text(
        json.dumps({"index.html": {"file": "assets/app.js", "css": ["assets/app.css"]}})
    )
    response = client.get("/ui?analysis=example")
    assert response.status_code == 200
    body: str = response.get_data(as_text=True)
    assert "/static/ui/assets/app.js" in body
    assert "/static/ui/assets/app.css" in body
    assert '"apiPrefix": "custom/api"' in body
    assert '"enabledEngines": ["reverse_dns"]' in body
    assert "secret" not in body.lower()
