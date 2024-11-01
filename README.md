# Cyberbro

A replacement for CyberGordon

# Getting Started

* To get started, clone the repository and install the requirements.

You might want to create a [`venv`](https://docs.python.org/3/library/venv.html) before installing the dependencies.

```bash
pip install -r requirements.txt
```

## Edit the config file

```
cp secrets-sample.json secrets.json
```

* Fill values (including proxy if needed) in the `secrets.json` file.

```json
{
    "virustotal": "token_here",
    "abuseipdb": "token_here",
    "ipinfo": "token_here",
    "google_safe_browsing": "token_here",
    "proxy_url": "",
    "spur_email": "spur_email_here",
    "spur_password": "spur_password_here"
}
```

# Launch the app

```
python3 app.py
```

```
* Serving Flask app 'app'
 * Debug mode: on
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on http://127.0.0.1:5000
Press CTRL+C to quit
 * Restarting with watchdog (windowsapi)
 * Debugger is active!
 * Debugger PIN: 820-969-550
```

* Go to http://127.0.0.1:5000 and Enjoy.

![image](https://github.com/user-attachments/assets/045c48ba-eabd-49ed-b4d8-58fd03e35780)

![image](https://github.com/user-attachments/assets/db009d2c-c611-4f2c-b7e9-21019e239197)

# Use docker

```bash
docker compose up -d
```

> Don't forget to edit the `secrets.json` before building the image.
