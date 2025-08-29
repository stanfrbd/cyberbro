## With docker

### The container cyberbro is running
1. ```docker exec -it cyberbro bash```
2. ```root@7b6e1c38676e:/app# nano secrets.json```
3. ```root@7b6e1c38676e:/app# service supervisor restart```
4. ```root@7b6e1c38676e:/app# exit```
5. Then go to http://127.0.0.1:5000 and use Cyberbro.

### The container cyberbro is not running
1. Edit `secrets.json` / `.env` with the updated values.
2. ```docker compose up --build --force-recreate -d```
3. Then go to http://127.0.0.1:5000 and use Cyberbro.

## Without docker
1. Edit `secrets.json` with the updated values.
2. Restart your `gunicorn` instance or start `supervisord` e.g. `service supervisord restart`
3. Then go to http://127.0.0.1:5000 and use Cyberbro.
