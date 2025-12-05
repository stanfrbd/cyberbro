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
    "dfir_iris_api_key": "token_here",
    "dfir_iris_url": "https://dfir-iris.local",
    "google_cse_cx": "cx_here",
    "google_cse_key": "key_here",
    "google_safe_browsing": "token_here",
    "ipapi": "token_here",
    "ipinfo": "token_here",
    "mde_client_id": "client_id_here",
    "mde_client_secret": "client_secret_here",
    "mde_tenant_id": "tenant_here",
    "misp_api_key": "token_here",
    "misp_url": "https://misp.local",
    "opencti_api_key": "token_here",
    "opencti_url": "https://demo.opencti.io",
    "proxy_url": "",
    "rl_analyze_api_key": "token_here",
    "rl_analyze_url": "https://spectra_analyse_url_here",
    "shodan": "token_here",
    "spur_us": "token_here",
    "threatfox": "token_here",
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

* **See more** in [Advanced deployment options](https://docs.cyberbro.net/quick-start/Advanced-options-for-deployment)

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
