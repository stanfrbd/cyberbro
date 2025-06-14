# Getting Started - TL;DR

!!! tip
    If you are lazy, you need Docker.  
    Do a `git clone` ; copy `secrets-sample.json` to `secrets.json` ; `docker compose up` then go to `localhost:5000`.  
    Yep, that's it!

<!-- termynal -->
```console
$ docker compose version
Docker Compose version v2.5.0
$ git clone https://github.com/stanfrbd/cyberbro
$ cd cyberbro
$ cp secrets-sample.json secrets.json
$ docker compose up --build # use -d to run in background

Go to http://127.0.0.1:5000/
```

## Getting Started

* To get started, clone the repository

```bash
git clone https://github.com/stanfrbd/cyberbro
cd cyberbro
```

## Edit the config file (mandatory)

```
cp secrets-sample.json secrets.json
```

!!! note
    Don't have API keys? No problem—just copy the `secrets-sample.json` to `secrets.json` and leave everything as is.

    Be careful if a proxy is used.  
    You will be able to use **all free engines!**


* Fill values (including proxy if needed) in the `secrets.json` file.

```json
{
    "abuseipdb": "token_here",
    "alienvault": "token_here",
    "criminalip_api_key": "token_here",
    "crowdstrike_client_id": "client_id_here",
    "crowdstrike_client_secret": "client_secret_here",
    "google_safe_browsing": "token_here",
    "ipinfo": "token_here",
    "mde_client_id": "client_id_here",
    "mde_client_secret": "client_secret_here",
    "mde_tenant_id": "tenant_here",
    "misp_api_key": "token_here",
    "misp_url": "https://misp.local",
    "opencti_api_key": "token_here",
    "opencti_url": "https://demo.opencti.io",
    "proxy_url": "",
    "shodan": "token_here",
    "virustotal": "token_here",
    "webscout": "token_here"
}
```

* Obtain API keys from the official documentation of each service.
* Microsoft Defender for Endpoint (MDE) is a paid service and can be skipped if you don't have an account (unchecked by default).

!!! info
    You can modify the configuration via the GUI at [http://127.0.0.1:5000/config](http://127.0.0.1:5000/config).  
    This endpoint is disabled by default for security reasons, as it is not protected.  
    To enable it, set `"config_page_enabled":true` in `secrets.json` or use `CONFIG_PAGE_ENABLED=true` as environment variable.  
    **This is not recommended for public or team use, as it exposes your API keys.**

## Launch the app

## Lazy and easy - use docker

!!! warning
    Make sure you install the `compose` plugin as `docker compose` and not `docker-compose`.

```bash
docker compose up # use -d to run in background and use --build to rebuild the image
```

* Go to http://127.0.0.1:5000 and Enjoy.

> Don't forget to edit the `secrets.json` before building the image.

## Using the docker image from GitHub Packages and a custom `docker compose` file

!!! tip
    All secrets values can be converted to environment variables (uppercase).  
    You can add these environment variables in a `docker-compose-custom.yml`. If you don't specify proxy, no proxy will be used.

```bash
PROXY_URL=http://127.0.0.1:9000
ALIENVAULT=api_key_here
VIRUSTOTAL=api_key_here
ABUSEIPDB=api_key_here
IPINFO=api_key_here
GOOGLE_SAFE_BROWSING=api_key_here
MDE_TENANT_ID=api_key_here
MDE_CLIENT_ID=api_key_here
MDE_CLIENT_SECRET=api_key_here
SHODAN=api_key_here
OPENCTI_API_KEY=api_key_here
OPENCTI_URL=https://demo.opencti.io
CROWDSTRIKE_CLIENT_ID=client_id_here
CROWDSTRIKE_CLIENT_SECRET=client_secret_here
CROWDSTRIKE_FALCON_BASE_URL=https://falcon.crowdstrike.com
WEBSCOUT=token_here
SUPERVISORD_WORKERS_COUNT=1
SUPERVISORD_THREADS_COUNT=1
SUPERVISORD_TIMEOUT=200
API_PREFIX=my_api
MAX_FORM_MEMORY_SIZE=1048576
GUI_ENABLED_ENGINES=reverse_dns,rdap
CONFIG_PAGE_ENABLED=true
SSL_VERIFY=true
GUI_CACHE_TIMEOUT=1800
API_CACHE_TIMEOUT=86400
```

## Example of custom docker compose file

!!! tip
    This can be useful when you don't want to build the image yourself. This image is produced by the GitHub actions workflow (must be authenticated).

```
ghcr.io/stanfrbd/cyberbro:latest
```

Example of `docker-compose-custom.yml` (note: no `"` in environment variables)

```
services:
  web:
    image: ghcr.io/stanfrbd/cyberbro:latest
    container_name: cyberbro
    ports:
      - "5000:5000"
    environment:
      - FLASK_ENV=production
      - VIRUSTOTAL=api_key_here
      - ABUSEIPDB=api_key_here
      - GUI_ENABLED_ENGINES=reverse_dns,rdap,ipquery,abuseipdb,virustotal,spur,google_safe_browsing,phishtank
    restart: always
    volumes:
      - ./data:/app/data
      - ./logs:/var/log/cyberbro
```

* **See more** in [Advanced deployment options](https://docs.cyberbro.net/quick-start/Advanced-options-for-deployment)

!!! note
    `./data:/app/data`: This maps the `data` directory on your host machine to the `/app/data` directory inside the container. This is mandatory for persisting the database `results.db` that is used by Cyberbro.  
    `./logs:/var/log/cyberbro`: This maps the `logs` directory on your host machine to the `/var/log/cyberbro` directory inside the container. This is useful for persisting log files generated by the application, allowing you to access and analyze logs even after the container is stopped or removed.

## The old way

* Clone the repository and install the requirements.

You might want to create a [`venv`](https://docs.python.org/3/library/venv.html) before installing the dependencies.

```bash
pip install -r requirements.txt
```

* Run the app with `gunicorn` (clean mode).

```bash
gunicorn -b 0.0.0.0:5000 app:app --timeout 120
```

* Run the app with in development mode.

```bash
python3 app.py
```

!!! warning
    `secrets.json` must be present according to the sample, before building image or launching.