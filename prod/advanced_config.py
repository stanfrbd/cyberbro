import configparser
import json
import os
from pathlib import Path

secrets_file = Path(__file__).parent.parent / "secrets.json"

# Path to the supervisord.conf file
supervisord_conf_file = Path(__file__).parent / "supervisord.conf"

# Read the secrets file if it exists
secrets = {}
if secrets_file.exists():
    with secrets_file.open() as f:
        secrets = json.load(f)

# Read the existing supervisord.conf
config = configparser.ConfigParser()
config.read(supervisord_conf_file)

supervisor_conf_edited = False

# Update the supervisord.conf with the new parameters if they exist
workers_count = secrets.get("supervisord_workers_count") or os.getenv("SUPERVISORD_WORKERS_COUNT")
threads_count = secrets.get("supervisord_threads_count") or os.getenv("SUPERVISORD_THREADS_COUNT")
timeout = secrets.get("supervisord_timeout") or os.getenv("SUPERVISORD_TIMEOUT")

if workers_count:
    config["program:cyberbro"]["command"] = config["program:cyberbro"]["command"].replace(
        "-w " + config["program:cyberbro"]["command"].split("-w ")[1].split()[0],
        f"-w {workers_count}",
    )
    supervisor_conf_edited = True

if threads_count:
    config["program:cyberbro"]["command"] = config["program:cyberbro"]["command"].replace(
        "-t " + config["program:cyberbro"]["command"].split("-t ")[1].split()[0],
        f"-t {threads_count}",
    )
    supervisor_conf_edited = True

if timeout:
    config["program:cyberbro"]["command"] = config["program:cyberbro"]["command"].replace(
        "--timeout " + config["program:cyberbro"]["command"].split("--timeout ")[1].split()[0],
        f"--timeout {timeout}",
    )
    supervisor_conf_edited = True

if supervisor_conf_edited:
    # Write the updated supervisord.conf
    with supervisord_conf_file.open("w") as configfile:
        config.write(configfile)
