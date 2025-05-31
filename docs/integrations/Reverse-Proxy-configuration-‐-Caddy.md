1. Install `caddy` using the [official documentation](https://caddyserver.com/docs/install#debian-ubuntu-raspbian)
2. Edit the Caddyfile
```
sudo nano /etc/caddy/Caddyfile
```
3. Add the following
```
# where example.com is your base domain
# 127.0.0.1 is your host. It can be the IP of the docker container.
cyberbro.example.com {
        reverse_proxy http://127.0.0.1:5000
        header {
            Access-Control-Allow-Origin https://cyberbro.example.com # be very careful, you can put * at your own risk.
        }
}
```
4. Reload the configuration
```
sudo systemctl reload caddy
```
or 
```
sudo service caddy reload
```

5. Access https://cyberbro.example.com (with an automatic Let's Encrypt certificate), that's great with `caddy`