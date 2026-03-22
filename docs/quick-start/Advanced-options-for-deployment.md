# Advanced options for deployment

!!! tip
    All variables from `secrets.json` can be converted to **environment variables** (uppercase).

!!! note
    You can add these environment variables in a `docker-compose-custom.yml` or just a `docker-compose-custom.yml` with a `.env`.  
    If you don't specify proxy, no proxy will be used.

!!! important
    Recommended usage:
    - If you want to change the exposed Docker port, prefer using a `.env` file for **all** configuration values.
    - If you keep the default Docker port mapping, using `secrets.json` remains sufficient.

!!! note
    Roadmap: we plan to progressively phase out `secrets.json` support in favor of `.env`-based configuration, which is more standard for container deployments.

Here is a list of all available environment variables that can be used with examples:

```bash
PROXY_URL=http://127.0.0.1:9000
VIRUSTOTAL=api_key_here
ALIENVAULT=api_key_here
ABUSEIPDB=api_key_here
IPAPI=api_key_here
IPINFO=api_key_here
GOOGLE_CSE_KEY=api_key_here
GOOGLE_CSE_CX=cx_here
GOOGLE_SAFE_BROWSING=api_key_here
MDE_TENANT_ID=api_key_here
MDE_CLIENT_ID=api_key_here
MDE_CLIENT_SECRET=api_key_here
MISP_URL=https://misp.local
MISP_API_KEY=api_key_here
SHODAN=api_key_here
SPUR_US=api_key_here
THREATFOX=api_key_here
OPENCTI_API_KEY=api_key_here
OPENCTI_URL=https://demo.opencti.io
CRIMINALIP_API_KEY=api_key_here
CROWDSTRIKE_CLIENT_ID=client_id_here
CROWDSTRIKE_CLIENT_SECRET=client_secret_here
CROWDSTRIKE_FALCON_BASE_URL=https://falcon.crowdstrike.com
DFIR_IRIS_URL=https://dfir-iris.local
DFIR_IRIS_API_KEY=token_here
WEBSCOUT=token_here
RL_ANALYZE_API_KEY=token_here
RL_ANALYZE_URL=https://spectra_analyze_url_here
ROSTI_API_KEY=token_here
GUNICORN_WORKERS_COUNT=4
GUNICORN_THREADS_COUNT=4
GUNICORN_TIMEOUT=200
FLASK_DEBUG=false
FLASK_PORT=5000
HOST_PORT=5000
FLASK_HOST=0.0.0.0
API_PREFIX=my_api
MAX_FORM_MEMORY_SIZE=1048576
GUI_ENABLED_ENGINES=reverse_dns,rdap_whois
CONFIG_PAGE_ENABLED=true
SSL_VERIFY=true
GUI_CACHE_TIMEOUT=1800
API_CACHE_TIMEOUT=86400
DISABLE_VERSION_CHECK=false
```

!!! tip
    This can be useful when you don't want to build the image yourself. This image is produced by the GitHub actions workflow

```
ghcr.io/stanfrbd/cyberbro:latest
```

Example of `docker-compose-custom.yml` (note: no `"` in environment variables)

!!! warning
    In Docker, `ports:` is resolved by Docker Compose **before** Cyberbro reads `secrets.json`.
    To keep networking predictable, use environment variables for Docker networking values (`FLASK_PORT`, `HOST_PORT`, `FLASK_HOST`).
    Keep `secrets.json` for API keys and app options.

```
services:
  web:
    image: ghcr.io/stanfrbd/cyberbro:latest
    container_name: cyberbro
    ports:
        - "${HOST_PORT:-5000}:${FLASK_PORT:-5000}"
    environment:
      - FLASK_ENV=production
      - ABUSEIPDB=${ABUSEIPDB:-}
      - ALIENVAULT=${ALIENVAULT:-}
      - CRIMINALIP_API_KEY=${CRIMINALIP_API_KEY:-}
      - CROWDSTRIKE_CLIENT_ID=${CROWDSTRIKE_CLIENT_ID:-}
      - CROWDSTRIKE_CLIENT_SECRET=${CROWDSTRIKE_CLIENT_SECRET:-}
      - CROWDSTRIKE_FALCON_BASE_URL=${CROWDSTRIKE_FALCON_BASE_URL:-}
      - DFIR_IRIS_API_KEY=${DFIR_IRIS_API_KEY:-}
      - DFIR_IRIS_URL=${DFIR_IRIS_URL:-}
      - GOOGLE_CSE_KEY=${GOOGLE_CSE_KEY:-}
      - GOOGLE_CSE_CX=${GOOGLE_CSE_CX:-}
      - GOOGLE_SAFE_BROWSING=${GOOGLE_SAFE_BROWSING:-}
      - IPAPI=${IPAPI:-}
      - IPINFO=${IPINFO:-}
      - MDE_CLIENT_ID=${MDE_CLIENT_ID:-}
      - MDE_CLIENT_SECRET=${MDE_CLIENT_SECRET:-}
      - MDE_TENANT_ID=${MDE_TENANT_ID:-}
      - MISP_API_KEY=${MISP_API_KEY:-}
      - MISP_URL=${MISP_URL:-}
      - OPENCTI_API_KEY=${OPENCTI_API_KEY:-}
      - OPENCTI_URL=${OPENCTI_URL:-}
      - RL_ANALYZE_API_KEY=${RL_ANALYZE_API_KEY:-}
      - RL_ANALYZE_URL=${RL_ANALYZE_URL:-}
      - ROSTI_API_KEY=${ROSTI_API_KEY:-}
      - SHODAN=${SHODAN:-}
      - SPUR_US=${SPUR_US:-}
      - THREATFOX=${THREATFOX:-}
      - VIRUSTOTAL=${VIRUSTOTAL:-}
      - WEBSCOUT=${WEBSCOUT:-}
      - CONFIG_PAGE_ENABLED=${CONFIG_PAGE_ENABLED:-}
      - SSL_VERIFY=${SSL_VERIFY:-}
      - PROXY_URL=${PROXY_URL:-}
        - GUI_CACHE_TIMEOUT=${GUI_CACHE_TIMEOUT:-1800}
        - API_CACHE_TIMEOUT=${API_CACHE_TIMEOUT:-86400}
      - GUI_ENABLED_ENGINES=${GUI_ENABLED_ENGINES:-}
      - GUNICORN_WORKERS_COUNT=${GUNICORN_WORKERS_COUNT:-}
      - GUNICORN_THREADS_COUNT=${GUNICORN_THREADS_COUNT:-}
      - GUNICORN_TIMEOUT=${GUNICORN_TIMEOUT:-}
      - FLASK_DEBUG=${FLASK_DEBUG:-}
        - FLASK_PORT=${FLASK_PORT:-5000}
        - FLASK_HOST=${FLASK_HOST:-0.0.0.0}
      - API_PREFIX=${API_PREFIX:-}
      - MAX_FORM_MEMORY_SIZE=${MAX_FORM_MEMORY_SIZE:-}
      - DISABLE_VERSION_CHECK=${DISABLE_VERSION_CHECK:-}
    restart: always
    volumes:
      - ./data:/app/data
      - ./logs:/var/log/cyberbro
```

Example of `.env` file (note: no `"` in environment variables)

```
VIRUSTOTAL=api_key_here
ABUSEIPDB=api_key_here
GUI_ENABLED_ENGINES=reverse_dns,rdap_whois,ipquery,abuseipdb,virustotal,spur,google_safe_browsing,phishtank
API_CACHE_TIMEOUT=1800
```

**You can use the file `.env.sample` as a template to create your own `.env` file.**

!!! danger
    Make sure you use either `secrets.json` or `.env` file for your deployment, not both.  
    This may lead to unexpected behavior as the application will try to read both files and may override some values.

!!! note
    `./data:/app/data`: This maps the `data` directory on your host machine to the `/app/data` directory inside the container. This is mandatory for persisting the database `results.db` that is used by Cyberbro.  
    `./logs:/var/log/cyberbro`: This maps the `logs` directory on your host machine to the `/var/log/cyberbro` directory inside the container. This is useful for persisting log files generated by the application, allowing you to access and analyze logs even after the container is stopped or removed.

## Gunicorn options

These options are applied via `prod/gunicorn.conf.py`, which reads them from `get_config()` at
startup.

**In `secrets.json`:**

* Adding `"gunicorn_workers_count": 4` in `secrets.json` will set the number of gunicorn worker processes
* Adding `"gunicorn_threads_count": 4` in `secrets.json` will set the number of threads per worker
* Adding `"gunicorn_timeout": 200` in `secrets.json` will set the worker timeout in seconds

**Or using environment variables:**

```bash
export GUNICORN_WORKERS_COUNT=4
export GUNICORN_THREADS_COUNT=4
export GUNICORN_TIMEOUT=200
```

!!! note
    These variables are optional. If they don't exist in `secrets.json` or ENV, the defaults (`workers=1`, `threads=1`, `timeout=120`) will be used.

## Flask server settings

These options control the interface and port that gunicorn/Flask binds to, as well as debug mode.

**`flask_debug`** — enables Flask debug mode (default: `false`).

!!! danger
    Never enable `flask_debug` in production. It exposes an interactive debugger and disables security features.

**In `secrets.json`:**

```json
"flask_debug": false
```

**Or using environment variables:**

```bash
export FLASK_DEBUG=false
```

______________________________________________________________________

**`flask_port`** — port that gunicorn/Flask binds to inside the container (default: `5000`).

!!! warning
    **In Docker**, the container-side port is mapped from `FLASK_PORT` in Compose (`"${HOST_PORT:-5000}:${FLASK_PORT:-5000}"`).
    If you change the internal bind port, set `FLASK_PORT` in `.env` (or shell env) so Compose and app use the same value.

**In `secrets.json`:**

```json
"flask_port": 5000
```

**Or using environment variables:**

```bash
export FLASK_PORT=5000
```

Optional (host side):

```bash
export HOST_PORT=5000
```

______________________________________________________________________

**`flask_host`** — network interface gunicorn binds to (default: `0.0.0.0`).

!!! warning
    **In Docker**, changing `flask_host` from `0.0.0.0` may prevent the container from being reachable on the mapped port.

**In `secrets.json`:**

```json
"flask_host": "0.0.0.0"
```

**Or using environment variables:**

```bash
export FLASK_HOST=0.0.0.0
```

!!! note
    All three Flask server settings are optional. If omitted, defaults are `flask_debug=false`, `flask_port=5000`, `flask_host=0.0.0.0`.
    In Docker, you can also set `HOST_PORT` (default `5000`) for the host-side mapping.

## API prefix in `app.py` and `index.html` options

**In `secrets.json`:**

!!! tip
    By default, the API is accessible at `http://cyberbro_instance:5000/api`

- Adding `"api_prefix": "my_api"` in `secrets.json` will set all the original prefix `/api/` endpoints to be renamed by prefix `/my_api/` endpoints in the files `app.py` and `index.html`

**Or using environment variables:**

```bash
export API_PREFIX=my_api
```

!!! note
    This variable is optional, so if it doesn't exist in `secrets.json`, the API will be accessible at `/api/` by default.

## Selected engines in the GUI (`index.html` only)

**In `secrets.json`:**

- Adding `"gui_enabled_engines": ["reverse_dns", "rdap_whois"]` in `secrets.json` will restrict usage of these two engines in the GUI.

**Or using environment variables:**

```bash
export GUI_ENABLED_ENGINES=reverse_dns,rdap_whois
```

!!! note
    This variable is optional, so if it doesn't exist in `secrets.json` or ENV, all engines will be displayed in the GUI.

!!! tip
    Example: for the demo instance of cyberbro, only these engines are used:
    `"gui_enabled_engines": ["reverse_dns", "rdap_whois", "ipquery", "abuseipdb", "virustotal", "spur", "google_safe_browsing", "shodan", "phishtank", "threatfox", "urlscan", "google", "github", "opencti", "abusix", "hudsonrock"]`  
    With environment variable: `GUI_ENABLED_ENGINES=reverse_dns,rdap_whois,ipquery,abuseipdb,virustotal,spur,google_safe_browsing,shodan,phishtank,threatfox,urlscan,google,github,opencti,abusix,hudsonrock`

## SSL verification settings for requests (backend)

!!! danger
    This is really insecure to disable it, do it at your own risk.

You can change the default behavior using the following:

**In `secrets.json`:**

Adding `"ssl_verify": false` in `secrets.json` will disable the certificate trust verification in the requests (backend).

**Or using environment variables:**

```bash
export SSL_VERIFY=false
```

!!! tip
    This variable is optional, so if it doesn't exist in `secrets.json` or ENV, it will use the default parameter (True) which is more secure.

## Config page in the GUI (`config.html`) http://cyberbro.local:5000/config

!!! danger
    This is unsecure so it is disabled by default.

You can add it using the following:

**In `secrets.json`:**

Adding `"config_page_enabled": true` in `secrets.json` will enable the config page in the GUI at http://cyberbro.local:5000/config

**Or using environment variables:**

```bash
export CONFIG_PAGE_ENABLED=true
```

!!! note
    This variable is optional, so if it doesn't exist in `secrets.json` or ENV, it will be disabled by default.

## Upload more than 1MB observables in the form

By default, the form in the GUI only accepts 1MB of data. You can change this limit using the following:

**In `secrets.json`:**

Adding `"max_form_memory_size": 1048576` in `secrets.json` will set the limit to 1MB (1048576 bytes) in the form.

**Or using environment variables:**

```bash
export MAX_FORM_MEMORY_SIZE=1048576
```

!!! note
    The value must be set in bytes, so 1MB = 1048576 bytes, 2MB = 2097152 bytes, etc.
    Don't set it too high, it can cause problems with the database or treatment of the data.  
    This variable is optional, so if it doesn't exist in `secrets.json` or ENV, it will use the default parameter (1MB).

[Flask doc about MAX_FORM_MEMORY_SIZE](https://flask.palletsprojects.com/en/stable/config/#MAX_FORM_MEMORY_SIZE)

## Cache timeout for the GUI

!!! note
    This is the timeout for the cache in the GUI, not the API.  
    The default value is 1800 seconds (30 minutes).  
    You can change this value using the following:

**In `secrets.json`:**

Adding `"gui_cache_timeout": 1800` in `secrets.json` will set the timeout to 30 minutes (1800 seconds) in the GUI.

**Or using environment variables:**

```bash
export GUI_CACHE_TIMEOUT=1800
```

!!! note
    The value must be set in seconds, so 1 minute = 60 seconds, 1 hour = 3600 seconds, etc.  
    Don't set it too high, it can cause problems with the database or treatment of the data.  
    This variable is optional, so if it doesn't exist in `secrets.json` or ENV, it will use the default parameter (30 minutes).

## Cache timeout for the API

!!! note
    This is the timeout for the cache in the API, not the GUI.  
    The default value is 86400 seconds (24 hours).  
    You can change this value using the following:

**In `secrets.json`:**

Adding `"api_cache_timeout": 86400` in `secrets.json` will set the timeout to 24 hours (86400 seconds) in the API.

**Or using environment variables:**

```bash
export API_CACHE_TIMEOUT=86400
```

!!! note
    The value must be set in seconds, so 1 minute = 60 seconds, 1 hour = 3600 seconds, etc.  
    Don't set it too high, it can cause problems with the database or treatment of the data.  
    This variable is optional, so if it doesn't exist in `secrets.json` or ENV, it will use the default parameter (24 hours).

## Disable version check

You can disable the version check and suppress the "new update available" popup using the following:

**In `secrets.json`:**

Adding `"disable_version_check": true` in `secrets.json` will disable the version check.

**Or using environment variables:**

```bash
export DISABLE_VERSION_CHECK=true
```

!!! note
    This variable is optional, so if it doesn't exist in `secrets.json` or ENV, it will use the default parameter (false) which means version check is enabled.
