import hashlib
import json
import logging
import threading
import time
import uuid
from dataclasses import asdict
from functools import lru_cache
from pathlib import Path

import ioc_fanger
import requests
from flask import Flask, jsonify, render_template, request, send_from_directory
from flask_caching import Cache
from flask_cors import CORS

from models.analysis_result import AnalysisResult, db
from utils.analysis import check_analysis_in_progress, perform_analysis
from utils.config import (
    BASE_DIR,
    SECRETS_FILE,
    Secrets,
    get_config,
    save_secrets_to_file,
)
from utils.export import export_to_csv, export_to_excel, prepare_data_for_export
from utils.stats import get_analysis_stats
from utils.utils import extract_observables

VERSION: str = "v0.9.5"


class InvalidCachefileError(Exception):
    pass


app: Flask = Flask(__name__)

logger: logging.Logger = logging.getLogger(__name__)

# Enable CORS, very permisive. If you want to restrict it, you can use the origins parameter (can break the GUI)
CORS(app)

# Ensure the data directory exists
DATA_DIR: Path = Path(BASE_DIR) / "data"
if not DATA_DIR.exists():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

# Read the secrets from the secrets.json file
secrets: Secrets = get_config()

# Cache configuration
app.config["CACHE_TYPE"] = "SimpleCache"
app.config["CACHE_DEFAULT_TIMEOUT"] = secrets.api_cache_timeout
logger.debug(f"CACHE_DEFAULT_TIMEOUT: {app.config['CACHE_DEFAULT_TIMEOUT']}")

cache: Cache = Cache(app)

# Retrieve from secrets or default to 1MB - MAX_FORM_MEMORY_SIZE is the maximum size of the form data in bytes
app.config["MAX_FORM_MEMORY_SIZE"] = secrets.max_form_memory_size
logger.debug(f"MAX_FORM_MEMORY_SIZE: {app.config['MAX_FORM_MEMORY_SIZE']}")

# Define API_PREFIX
API_PREFIX: str = secrets.api_prefix

# Enable the config page - not intended for public use since authentication is not implemented
app.config["CONFIG_PAGE_ENABLED"] = secrets.config_page_enabled

# Define GUI_ENABLED_ENGINES
GUI_ENABLED_ENGINES: list = secrets.gui_enabled_engines

# Update the database URI to use the data directory
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DATA_DIR / 'results.db'}"

# Disable modification tracking to save memory
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Set the size of the database connection pool
app.config["SQLALCHEMY_POOL_SIZE"] = 10

# Set the maximum overflow size of the connection pool
app.config["SQLALCHEMY_MAX_OVERFLOW"] = 20

# Set version
app.config["VERSION"] = VERSION

# Initialize the database
db.init_app(app)

# Create the database tables if they do not exist
with app.app_context():
    db.create_all()

PROXIES: dict[str, str] = {"https": secrets.proxy_url, "http": secrets.proxy_url}

SSL_VERIFY: bool = secrets.ssl_verify


def get_latest_version_from_cache_file(cache_file: Path) -> str:
    """Check if the cache file exists and is not older than a day.

    Return True if the cache file is valid and recent, False otherwise.
    """

    if not cache_file.exists():
        raise InvalidCachefileError("Cache file does not exist.")

    try:
        with cache_file.open() as f:
            try:
                cache_data = json.load(f)
            except json.JSONDecodeError as e:
                print("Cache file is corrupted, fetching latest version.")
                logger.warning("Cache file is corrupted, fetching latest version.")
                raise InvalidCachefileError("Cache file is corrupted.") from e

            last_checked = cache_data["last_checked"]
            if time.time() - last_checked > 86400:
                raise InvalidCachefileError("Cache file is too old.")
    except (OSError, KeyError) as e:
        raise InvalidCachefileError("Cache file is not readable.") from e

    return cache_data.get("latest_version", "")


def get_latest_version_from_updated_cache_file(cache_file: Path) -> str:
    """Update the cache file with the latest version and current time."""

    url: str = "https://api.github.com/repos/stanfrbd/cyberbro/releases/latest"

    if not cache_file.exists():
        cache_file.touch()

    try:
        response = requests.get(url, proxies=PROXIES, verify=SSL_VERIFY, timeout=5)
        response.raise_for_status()
        latest_release: dict = response.json()
        latest_version = latest_release.get("tag_name", "")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching latest version: {e}")
        return ""
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON response: {e}")
        return ""

    try:
        with cache_file.open("w") as f:
            json.dump({"last_checked": time.time(), "latest_version": latest_version}, f)
            logger.info(f"Cache file updated with latest version: {latest_version}")
    except OSError as e:
        logger.error(f"Error writing to cache file: {e}")

    return latest_version


@lru_cache
def check_for_new_version(current_version: str) -> bool:
    """Check if a new version of the application is available."""

    cache_file: Path = DATA_DIR / "version_cache.json"

    # Check if cache file exists and is not older than a day
    try:
        latest_version: str = get_latest_version_from_cache_file(cache_file)
    except InvalidCachefileError:
        latest_version: str = get_latest_version_from_updated_cache_file(cache_file)

    return latest_version != current_version


@app.route("/")
def index():
    """Render the index page."""

    new_version_available: bool = check_for_new_version(app.config["VERSION"])

    return render_template(
        "index.html",
        results=[],
        API_PREFIX=API_PREFIX,
        GUI_ENABLED_ENGINES=GUI_ENABLED_ENGINES,
        new_version_available=new_version_available,
    )


@app.route("/analyze", methods=["POST"])
def analyze():
    """Handle the analyze request with caching and an option to ignore cache."""
    form_data = ioc_fanger.fang(request.form.get("observables", ""))
    observables = extract_observables(form_data)
    selected_engines = request.form.getlist("engines")
    ignore_cache = request.args.get("ignore_cache", "false").lower() == "true"

    # Generate a secure hash for form data and engines using SHA-256
    combined_data = f"{form_data}|{','.join(selected_engines)}"
    cache_key = f"web-analyze-{hashlib.sha256(combined_data.encode('utf-8')).hexdigest()}"

    if not ignore_cache:
        # Check cache
        cached_result = cache.get(cache_key)
        if cached_result:
            logger.debug(f"Cache hit: {cache_key}")
            logger.debug(f"Cached result: {cached_result}")
            return render_template(
                "waiting.html",
                analysis_id=cached_result["analysis_id"],
                API_PREFIX=API_PREFIX,
            ), 200

    # If no cache
    analysis_id = str(uuid.uuid4())
    threading.Thread(target=perform_analysis, args=(app, observables, selected_engines, analysis_id)).start()

    # Generate response
    response_data = {"analysis_id": analysis_id}
    # Store in cache with a custom timeout from secrets or default to 30 minutes
    gui_cache_timeout = secrets.gui_cache_timeout
    cache.set(cache_key, response_data, timeout=gui_cache_timeout)

    return render_template("waiting.html", analysis_id=analysis_id, API_PREFIX=API_PREFIX), 200


@app.route("/results/<analysis_id>", methods=["GET"])
def show_results(analysis_id):
    """Show the results of the analysis."""

    # If URL includes "?display=table", force a table view of results
    display: str = request.args.get("display", "default")
    analysis_results = db.session.get(AnalysisResult, analysis_id)
    if analysis_results:
        return render_template(
            "results.html",
            analysis_results=analysis_results,
            API_PREFIX=API_PREFIX,
            display_mode=display,
        )
    return render_template("404.html"), 404


@app.route(f"/{API_PREFIX}/is_analysis_complete/<analysis_id>", methods=["GET"])
def is_analysis_complete(analysis_id):
    """Check if the analysis is complete."""
    complete = not check_analysis_in_progress(analysis_id)
    return jsonify({"complete": complete})


@app.route("/export/<analysis_id>")
def export(analysis_id):
    """Export the analysis results."""
    format = request.args.get("format")
    analysis_results = db.session.get(AnalysisResult, analysis_id)
    data = prepare_data_for_export(analysis_results)
    timestamp = time.strftime("%Y-%m-%d_%H_%M_%S", time.localtime())

    if format == "csv":
        return export_to_csv(data, timestamp)
    if format == "excel":
        return export_to_excel(data, timestamp)
    return jsonify({"error": "Invalid export format requested."}), 400


@app.route("/favicon.ico")
def favicon():
    """Serve the favicon."""
    return send_from_directory(
        Path(app.root_path) / "images",
        "favicon.ico",
        mimetype="image/vnd.microsoft.icon",
    )


@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_server_error(e):
    """Handle 500 errors."""
    return render_template("500.html"), 500


@app.errorhandler(413)
def request_entity_too_large(e):
    """Handle 413 errors."""
    return render_template("413.html"), 413


@app.route("/history")
def history():
    """Render the history page."""
    analysis_results = (
        db.session.query(AnalysisResult)
        .filter(AnalysisResult.results != [])
        .order_by(AnalysisResult.end_time.desc())
        .limit(60)
        .all()
    )
    return render_template("history.html", analysis_results=analysis_results)


@app.route("/stats")
def stats():
    """Render the stats page."""
    stats = get_analysis_stats()
    return render_template("stats.html", stats=stats)


@app.route("/about")
def about():
    """Render the about page."""
    return render_template("about.html", version=app.config["VERSION"])


@app.route("/config")
def config():
    """Render the config page."""
    if not app.config.get("CONFIG_PAGE_ENABLED", False):
        return render_template("404.html"), 404
    return render_template("config.html", secrets=asdict(secrets))


@app.route("/update_config", methods=["POST"])
def update_config():
    """Update config from the form data"""
    if not app.config.get("CONFIG_PAGE_ENABLED", False):
        return jsonify({"message": "Configuration update is disabled."}), 403
    try:
        secrets.proxy_url = request.form.get("proxy_url", secrets.proxy_url)
        secrets.virustotal = request.form.get("virustotal", secrets.virustotal)
        secrets.abuseipdb = request.form.get("abuseipdb", secrets.abuseipdb)
        secrets.ipinfo = request.form.get("ipinfo", secrets.ipinfo)
        secrets.google_safe_browsing = request.form.get("google_safe_browsing", secrets.google_safe_browsing)
        secrets.mde_tenant_id = request.form.get("mde_tenant_id", secrets.mde_tenant_id)
        secrets.mde_client_id = request.form.get("mde_client_id", secrets.mde_client_id)
        secrets.mde_client_secret = request.form.get("mde_client_secret", secrets.mde_client_secret)
        secrets.shodan = request.form.get("shodan", secrets.shodan)
        secrets.opencti_api_key = request.form.get("opencti_api_key", secrets.opencti_api_key)
        secrets.opencti_url = request.form.get("opencti_url", secrets.opencti_url)
        secrets.crowdstrike_client_id = request.form.get("crowdstrike_client_id", secrets.crowdstrike_client_id)
        secrets.crowdstrike_client_secret = request.form.get(
            "crowdstrike_client_secret", secrets.crowdstrike_client_secret
        )
        secrets.crowdstrike_falcon_base_url = request.form.get(
            "crowdstrike_falcon_base_url", secrets.crowdstrike_falcon_base_url
        )
        secrets.webscout = request.form.get("webscout", secrets.webscout)
        secrets.threatfox = request.form.get("threatfox", secrets.threatfox)
        secrets.dfir_iris_api_key = request.form.get("dfir_iris_api_key", secrets.dfir_iris_api_key)
        secrets.dfir_iris_url = request.form.get("dfir_iris_url", secrets.dfir_iris_url)

        # Apply the GUI_ENABLED_ENGINES configuration directly to the GUI to avoid restarting the app
        updated_gui_enabled_engines: str = request.form.get("gui_enabled_engines", "")
        if updated_gui_enabled_engines:
            global GUI_ENABLED_ENGINES
            secrets.gui_enabled_engines = [engine.strip().lower() for engine in updated_gui_enabled_engines.split(",")]
            GUI_ENABLED_ENGINES = secrets.gui_enabled_engines

        # Save the secrets to the secrets.json file
        save_secrets_to_file(secrets, SECRETS_FILE)

        message = "Configuration updated successfully."
    except Exception as e:
        message = f"An error occurred while updating the configuration. {e}"
    return jsonify({"message": message})


@app.route(f"/{API_PREFIX}/results/<analysis_id>", methods=["GET"])
def get_results(analysis_id):
    """Get the results of the analysis."""
    analysis_results = db.session.get(AnalysisResult, analysis_id)
    if analysis_results:
        return jsonify(analysis_results.results)
    return jsonify({"error": "Analysis not found."}), 404


@app.route(f"/{API_PREFIX}/analyze", methods=["POST"])
def analyze_api():
    """Handle the analyze request via API with caching and hashing."""
    data = request.get_json()
    form_data = ioc_fanger.fang(data.get("text", ""))
    selected_engines = data.get("engines", [])
    ignore_cache = data.get("ignore_cache", False)

    # Generate a secure hash for form data and engines using SHA-256
    combined_data = f"{form_data}|{','.join(selected_engines)}"
    cache_key = f"api-analyze-{hashlib.sha256(combined_data.encode('utf-8')).hexdigest()}"

    if not ignore_cache:
        # Check cache
        cached_result = cache.get(cache_key)
        if cached_result:
            logger.debug(f"Cache hit: {cache_key}")
            logger.debug(f"Cached result: {cached_result}")
            return jsonify(cached_result), 200

    # If no cache
    analysis_id = str(uuid.uuid4())
    threading.Thread(
        target=perform_analysis,
        args=(app, extract_observables(form_data), selected_engines, analysis_id),
    ).start()

    # Generate response
    response_data = {"analysis_id": analysis_id, "link": f"/results/{analysis_id}"}
    response = jsonify(response_data)

    # Store in cache with the specified timeout for the API (api_cache_timeout)
    cache.set(cache_key, response_data)

    return response, 200


@app.route("/graph/<analysis_id>", methods=["GET"])
def graph(analysis_id):
    """Render the graph visualization for the given analysis ID."""
    analysis_results = db.session.get(AnalysisResult, analysis_id)
    if analysis_results:
        return render_template("graph.html", analysis_id=analysis_id, API_PREFIX=API_PREFIX), 200
    return render_template("404.html"), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
