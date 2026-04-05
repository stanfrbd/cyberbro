#!/bin/bash

set -eu

if [ "$#" -eq 0 ]; then
    echo "[bootstrap] error: no startup command provided"
    exit 1
fi

# Remove stale version cache after upgrades so update checks are refreshed.
rm -f "data/version_cache.json"

# Bootstrap phase (root): fix ownership on mounted paths when needed.
# Runtime phase (non-root): execute the app command as cyberbro.
if [ "$(id -u)" -eq 0 ]; then
    /app/prod/fix_ownership.sh

    # gosu performs a direct setuid/setgid + exec and avoids the extra
    # session/signal behaviors of su/sudo in containers.
    if ! command -v gosu >/dev/null 2>&1; then
        echo "[bootstrap] error: 'gosu' is required to drop privileges to cyberbro"
        exit 1
    fi

    exec gosu cyberbro "$@"
fi

# If container already runs as non-root, continue with app entrypoint.
exec "$@"
