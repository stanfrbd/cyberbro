# Getting Started - TL;DR

!!! tip
    If you are lazy, use Docker.
    Do a `git clone` ; copy `.env.sample` to `.env` ; `docker compose up` then go to `localhost:5000`.

<!-- termynal -->
```console
$ docker compose version
Docker Compose version v2.5.0
$ git clone https://github.com/stanfrbd/cyberbro
$ cd cyberbro
$ cp .env.sample .env
$ docker compose up --build

Go to http://127.0.0.1:5000/
```

## Getting Started

* Clone the repository:

```bash
git clone https://github.com/stanfrbd/cyberbro
cd cyberbro
```

* Create your environment file:

```bash
cp .env.sample .env
```

* Fill your `.env` values (API keys, proxy, runtime options).

!!! note
    No API keys yet? Keep `.env` mostly empty and start with free engines.

!!! warning
    Do not commit `.env` in Git.

!!! danger
    For production/team use, store `.env` secrets with SOPS, Vault, or an equivalent secrets manager.

See [Advanced options for deployment](https://docs.cyberbro.net/quick-start/Advanced-options-for-deployment) for the full list of variables and migration guidance.

## Launch the app

## Lazy and easy - use Docker

!!! warning
    Make sure you install the `compose` plugin as `docker compose` and not `docker-compose`.

```bash
docker compose up # use -d to run in background and use --build to rebuild the image
```

* Go to http://127.0.0.1:5000 and enjoy.

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
gunicorn -c prod/gunicorn.conf.py app:app
```

!!! note
    When running without Docker, gunicorn behavior is controlled by environment variables such as `FLASK_PORT`, `FLASK_HOST`, `GUNICORN_WORKERS_COUNT`, `GUNICORN_THREADS_COUNT`, and `GUNICORN_TIMEOUT`.

* Run the app in development mode.

```bash
python3 app.py
```
