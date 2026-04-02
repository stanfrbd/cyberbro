## With docker
1. Edit `.env` on the host machine (next to `docker-compose.yml`).
2. Recreate the container so new environment variables are injected:
	```bash
	docker compose up --build --force-recreate -d
	```
3. Then go to http://127.0.0.1:5000 and use Cyberbro.

## Without docker
1. Edit `.env` (or exported environment variables) with the updated values.
2. Restart your `gunicorn` instance or start `supervisord` e.g. `service supervisord restart`
3. Then go to http://127.0.0.1:5000 and use Cyberbro.
