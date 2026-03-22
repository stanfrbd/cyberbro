#!/bin/bash

# Deletes the version cache file if it exists - useful after updating the app
if [ -f "data/version_cache.json" ]; then
    rm "data/version_cache.json"
fi

# Start supervisord
/usr/bin/supervisord -c /app/prod/supervisord.conf
