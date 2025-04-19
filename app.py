import os
import json
import time
import uuid
import threading
import requests
import logging
from flask import Flask, request, render_template, jsonify, send_from_directory
from flask_cors import CORS

import ioc_fanger
from utils.config import get_config, BASE_DIR, SECRETS_FILE
from utils.utils import extract_observables
from utils.export import prepare_data_for_export, export_to_csv, export_to_excel
from models.analysis_result import AnalysisResult, db
from utils.stats import get_analysis_stats
from utils.analysis import perform_analysis, check_analysis_in_progress
from flask_caching import Cache
import hashlib

app = Flask(__name__)

logger = logging.getLogger(__name__)

# Enable CORS, very permisive. If you want to restrict it, you can use the origins parameter (can break the GUI)
CORS(app)

# Ensure the data directory exists
DATA_DIR = os.path.join(BASE_DIR, 'data')
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

# Read the secrets from the secrets.json file
secrets = get_config()

# Cache configuration
app.config['CACHE_TYPE'] = 'SimpleCache'
app.config['CACHE_DEFAULT_TIMEOUT'] = secrets.get("api_cache_timeout", 86400)  # Default to 1 day
logger.debug(f"CACHE_DEFAULT_TIMEOUT: {app.config['CACHE_DEFAULT_TIMEOUT']}")

cache = Cache(app)

# Retrieve from secrets or default to 1MB - MAX_FORM_MEMORY_SIZE is the maximum size of the form data in bytes
app.config['MAX_FORM_MEMORY_SIZE'] = secrets.get("max_form_memory_size", 1 * 1024 * 1024)
logger.debug(f"MAX_FORM_MEMORY_SIZE: {app.config['MAX_FORM_MEMORY_SIZE']}")

# Define API_PREFIX
API_PREFIX = secrets.get("api_prefix", "api")

# Enable the config page - not intended for public use since authentication is not implemented
app.config['CONFIG_PAGE_ENABLED'] = secrets.get("config_page_enabled", False)

# Define GUI_ENABLED_ENGINES
GUI_ENABLED_ENGINES = secrets.get("gui_enabled_engines", [])

# Update the database URI to use the data directory
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(DATA_DIR, 'results.db')}"

# Disable modification tracking to save memory
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Set the size of the database connection pool
app.config['SQLALCHEMY_POOL_SIZE'] = 10

# Set the maximum overflow size of the connection pool
app.config['SQLALCHEMY_MAX_OVERFLOW'] = 20

# Set version 
app.config['VERSION'] = "v0.6.4"

# Initialize the database
db.init_app(app)

# Create the database tables if they do not exist
with app.app_context():
    db.create_all()

PROXIES = { "https": secrets["proxy_url"], "http": secrets["proxy_url"] }

SSL_VERIFY = secrets.get("ssl_verify", True)

def check_new_version(current_version):
    url = "https://api.github.com/repos/stanfrbd/cyberbro/releases/latest"
    cache_file = os.path.join(DATA_DIR, 'version_cache.json')

    try:
        # Check if cache file exists and is not older than a day
        if os.path.exists(cache_file):
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)
                last_checked = cache_data.get('last_checked')
                if last_checked and time.time() - last_checked < 86400:
                    return cache_data.get('latest_version') != current_version

        # If cache is older than a day or doesn't exist, fetch the latest version
        response = requests.get(url, proxies=PROXIES, verify=SSL_VERIFY, timeout=5)
        latest_release = response.json()
        latest_version = latest_release["tag_name"]

        # Update the cache
        with open(cache_file, 'w') as f:
            json.dump({'last_checked': time.time(), 'latest_version': latest_version}, f)

        return latest_version != current_version
    except Exception as e:
        logger.error(f"Error checking for new version: {e}")
        return False

@app.route('/')
def index():
    """Render the index page."""
    new_version_available = check_new_version(app.config['VERSION'])
    return render_template('index.html', results=[], API_PREFIX=API_PREFIX, GUI_ENABLED_ENGINES=GUI_ENABLED_ENGINES, new_version_available=new_version_available)

@app.route('/analyze', methods=['POST'])
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
            return render_template('waiting.html', analysis_id=cached_result['analysis_id'], API_PREFIX=API_PREFIX), 200

    # If no cache
    analysis_id = str(uuid.uuid4())
    threading.Thread(target=perform_analysis, args=(app, observables, selected_engines, analysis_id)).start()

    # Generate response
    response_data = {'analysis_id': analysis_id}
    # Store in cache with a custom timeout from secrets or default to 30 minutes
    gui_cache_timeout = secrets.get("gui_cache_timeout", 30 * 60)  # Default to 30 minutes
    cache.set(cache_key, response_data, timeout=gui_cache_timeout)

    return render_template('waiting.html', analysis_id=analysis_id, API_PREFIX=API_PREFIX), 200

@app.route('/results/<analysis_id>', methods=['GET'])
def show_results(analysis_id):
    """Show the results of the analysis."""
    analysis_results = db.session.get(AnalysisResult, analysis_id)
    if analysis_results:
        return render_template('index.html', analysis_results=analysis_results, API_PREFIX=API_PREFIX)
    else:
        return render_template('404.html'), 404

@app.route(f'/{API_PREFIX}/is_analysis_complete/<analysis_id>', methods=['GET'])
def is_analysis_complete(analysis_id):
    """Check if the analysis is complete."""
    complete = not check_analysis_in_progress(analysis_id)
    return jsonify({'complete': complete})

@app.route('/export/<analysis_id>')
def export(analysis_id):
    """Export the analysis results."""
    format = request.args.get('format')
    analysis_results = db.session.get(AnalysisResult, analysis_id)
    data = prepare_data_for_export(analysis_results)
    timestamp = time.strftime("%Y-%m-%d_%H_%M_%S", time.localtime())

    if format == 'csv':
        return export_to_csv(data, timestamp)
    elif format == 'excel':
        return export_to_excel(data, timestamp)

@app.route('/favicon.ico')
def favicon():
    """Serve the favicon."""
    return send_from_directory(os.path.join(app.root_path, 'images'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    """Handle 500 errors."""
    return render_template('500.html'), 500

@app.errorhandler(413)
def request_entity_too_large(e):
    """Handle 413 errors."""
    return render_template('413.html'), 413

@app.route('/history')
def history():
    """Render the history page."""
    analysis_results = db.session.query(AnalysisResult).filter(AnalysisResult.results != []).order_by(AnalysisResult.end_time.desc()).limit(60).all()
    return render_template('history.html', analysis_results=analysis_results)

@app.route('/stats')
def stats():
    """Render the stats page."""
    stats = get_analysis_stats()
    return render_template('stats.html', stats=stats)

@app.route('/about')
def about():
    """Render the about page."""
    return render_template('about.html', version=app.config['VERSION'])

@app.route('/config')
def config():
    """Render the config page."""
    if not app.config.get('CONFIG_PAGE_ENABLED', False):
        return render_template('404.html'), 404
    return render_template('config.html', secrets=secrets)

@app.route('/update_config', methods=['POST'])
def update_config():
    """Update config from the form data"""
    if not app.config.get('CONFIG_PAGE_ENABLED', False):
        return jsonify({'message': 'Configuration update is disabled.'}), 403
    try:
        secrets["proxy_url"] = request.form.get("proxy_url", secrets.get("proxy_url", ""))
        secrets["virustotal"] = request.form.get("virustotal", secrets.get("virustotal", ""))
        secrets["abuseipdb"] = request.form.get("abuseipdb", secrets.get("abuseipdb", ""))
        secrets["ipinfo"] = request.form.get("ipinfo", secrets.get("ipinfo", ""))
        secrets["google_safe_browsing"] = request.form.get("google_safe_browsing", secrets.get("google_safe_browsing", ""))
        secrets["mde_tenant_id"] = request.form.get("mde_tenant_id", secrets.get("mde_tenant_id", ""))
        secrets["mde_client_id"] = request.form.get("mde_client_id", secrets.get("mde_client_id", ""))
        secrets["mde_client_secret"] = request.form.get("mde_client_secret", secrets.get("mde_client_secret", ""))
        secrets["shodan"] = request.form.get("shodan", secrets.get("shodan", ""))
        secrets["opencti_api_key"] = request.form.get("opencti_api_key", secrets.get("opencti_api_key", ""))
        secrets["opencti_url"] = request.form.get("opencti_url", secrets.get("opencti_url", ""))
        secrets["crowdstrike_client_id"] = request.form.get("crowdstrike_client_id", secrets.get("crowdstrike_client_id", ""))
        secrets["crowdstrike_client_secret"] = request.form.get("crowdstrike_client_secret", secrets.get("crowdstrike_client_secret", ""))
        secrets["crowdstrike_falcon_base_url"] = request.form.get("crowdstrike_falcon_base_url", secrets.get("crowdstrike_falcon_base_url", "https://falcon.crowdstrike.com"))
        secrets["webscout"] = request.form.get("webscout", secrets.get("webscout", ""))
        
        # Apply the GUI_ENABLED_ENGINES configuration directly to the GUI to avoid restarting the app
        global GUI_ENABLED_ENGINES
        GUI_ENABLED_ENGINES = request.form.get("gui_enabled_engines", "")
        secrets["gui_enabled_engines"] = [engine.strip().lower() for engine in GUI_ENABLED_ENGINES.split(",")] if GUI_ENABLED_ENGINES else []
        GUI_ENABLED_ENGINES = secrets["gui_enabled_engines"]
        
        # Save the secrets to the secrets.json file
        with open(SECRETS_FILE, 'w') as f:
            json.dump(secrets, f, indent=4)
        
        message = "Configuration updated successfully."
    except Exception as e:
        message = f"An error occurred while updating the configuration. {e}"
    return jsonify({'message': message})

@app.route(f'/{API_PREFIX}/results/<analysis_id>', methods=['GET'])
def get_results(analysis_id):
    """Get the results of the analysis."""
    analysis_results = db.session.get(AnalysisResult, analysis_id)
    if analysis_results:
        return jsonify(analysis_results.results)
    else:
        return jsonify({'error': 'Analysis not found.'}), 404

@app.route(f'/{API_PREFIX}/analyze', methods=['POST'])
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
    threading.Thread(target=perform_analysis, args=(app, extract_observables(form_data), selected_engines, analysis_id)).start()

    # Generate response
    response_data = {'analysis_id': analysis_id, 'link': f"/results/{analysis_id}"}
    response = jsonify(response_data)

    # Store in cache with the specified timeout for the API (api_cache_timeout)
    cache.set(cache_key, response_data)

    return response, 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)