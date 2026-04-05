#!/bin/bash

set -eu

exec /usr/local/bin/gunicorn -c prod/gunicorn.conf.py app:app
