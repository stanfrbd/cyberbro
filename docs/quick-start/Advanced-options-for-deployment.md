# Advanced options for deployment

!!! danger
    `.env` contains secrets. Never commit it.  
    For production/team use, protect secrets with SOPS, Vault, cloud secret managers, or an equivalent secure workflow.

!!! warning
    Starting with version `v0.13.0`, Cyberbro no longer supports `secrets.json` and the `/config` GUI page.

## Recommended workflow

1. Copy the sample file:

```bash
cp .env.sample .env
```

2. Edit `.env` and set your API keys and runtime settings.

3. Start Cyberbro:

```bash
docker compose up --build
```

## Runtime loading behavior

At startup, Cyberbro tries to load `.env` from the project root.
If `.env` is missing, Cyberbro falls back to process environment variables and logs a debug-level message (no warning is emitted, so production deployments using injected env vars will not see spurious log noise).

## Migration from legacy `secrets.json`

If you have an existing `secrets.json` file, use the migration helper script to convert it to the new `.env` format:

```bash
python3 scripts/secrets_json_to_env.py
```

Script location: `scripts/secrets_json_to_env.py`

Optional custom paths:

```bash
python3 scripts/secrets_json_to_env.py \
  --secrets secrets.json \
  --output .env \
  --env-sample .env.sample
```

After migration:

1. Review generated `.env` values.
2. Remove `secrets.json` from runtime usage.
3. Restart Cyberbro.

## Full list of supported environment variables with example values

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
MDE_TENANT_ID=tenant_here
MDE_CLIENT_ID=client_id_here
MDE_CLIENT_SECRET=client_secret_here
MISP_URL=https://misp.local
MISP_API_KEY=api_key_here
MISP_FEEDBACK_SERVER_URL=https://misp-feedback.local
MISP_FEEDBACK_TOKEN=token_here
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
FLASK_HOST=127.0.0.1
API_PREFIX=my_api
MAX_FORM_MEMORY_SIZE=1048576
SSL_VERIFY=true
GUI_CACHE_TIMEOUT=1800
API_CACHE_TIMEOUT=86400
GUI_ENABLED_ENGINES=reverse_dns,rdap_whois
DISABLE_VERSION_CHECK=false
```

## Docker image usage

!!! tip
    You can run the public image built by GitHub Actions:

```text
ghcr.io/stanfrbd/cyberbro:latest
```

Example `docker-compose-custom.yml` (note: no quotes in environment variable values):

```yaml
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
      - MISP_FEEDBACK_SERVER_URL=${MISP_FEEDBACK_SERVER_URL:-}
      - MISP_FEEDBACK_TOKEN=${MISP_FEEDBACK_TOKEN:-}
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
      - FLASK_HOST=0.0.0.0
      - API_PREFIX=${API_PREFIX:-}
      - MAX_FORM_MEMORY_SIZE=${MAX_FORM_MEMORY_SIZE:-}
      - DISABLE_VERSION_CHECK=${DISABLE_VERSION_CHECK:-}
    restart: always
    volumes:
      - ./data:/app/data
      - ./logs:/var/log/cyberbro
```

Example `.env`:

```bash
VIRUSTOTAL=api_key_here
ABUSEIPDB=api_key_here
GUI_ENABLED_ENGINES=reverse_dns,rdap_whois,ipquery,abuseipdb,virustotal
API_CACHE_TIMEOUT=1800
```

## Notes by setting

### Gunicorn options

Set:

```bash
export GUNICORN_WORKERS_COUNT=4
export GUNICORN_THREADS_COUNT=4
export GUNICORN_TIMEOUT=200
```

Defaults: `workers=1`, `threads=1`, `timeout=120`.

### Flask server settings

```bash
export FLASK_DEBUG=false
export FLASK_PORT=5000
export FLASK_HOST=127.0.0.1
export HOST_PORT=5000
```

!!! warning
    In Docker, keep `FLASK_PORT` and `HOST_PORT` aligned with your `ports:` mapping.
    `FLASK_HOST` is forced to `0.0.0.0` in the container so a local `127.0.0.1` from your shell or `.env` cannot break exposure.

### API prefix

```bash
export API_PREFIX=my_api
```

Default: `api`.

### Selected engines in GUI

```bash
export GUI_ENABLED_ENGINES=reverse_dns,rdap_whois
```

If unset, all engines are displayed.

### SSL verification

```bash
export SSL_VERIFY=false
```

!!! danger
    Disabling SSL verification is insecure. Use only for controlled troubleshooting.

### Form upload size

```bash
export MAX_FORM_MEMORY_SIZE=1048576
```

Default: 1 MB.

### Cache timeout

```bash
export GUI_CACHE_TIMEOUT=1800
export API_CACHE_TIMEOUT=86400
```

### Disable version check

```bash
export DISABLE_VERSION_CHECK=true
```

## Related documentation

- [API usage and engine names](https://docs.cyberbro.net/quick-start/API-usage-and-engine-names)
