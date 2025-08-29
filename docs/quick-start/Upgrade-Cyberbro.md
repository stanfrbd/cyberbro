# With docker

## Using the `git` repo

* Go to your cyberbro directory (e.g. `/opt/cyberbro`).
* `docker compose down` (optional)
* `git pull`
* `docker compose up --build --force-recreate -d`
!!! warning
    Be careful that your `secrets.json` / `.env` is up to date.

## Using the image from GitHub packages

!!! info
    Assuming you already have a valid custom docker compose file using the image `ghcr.io/stanfrbd/cyberbro:latest`

* Go to your cyberbro directory (e.g. `/opt/cyberbro`) where your custom `docker compose` file is located.

```
docker compose down # optional
docker-compose up -d --pull always --force-recreate
```

!!! warning
    Be careful that your environment variables / `.env` and your custom `docker compose` file are up to date.

# Without docker

* Go to your cyberbro directory (e.g. `/opt/cyberbro`).
* `git pull`
* `pip install -r requirements.txt`
* `rm data/version_cache.json`
* `gunicorn -b 0.0.0.0:5000 app:app --timeout 120` (or using `supervisord.conf`)

!!! warning
    Be careful that your `secrets.json` is up to date
