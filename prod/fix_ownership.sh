#!/bin/bash

set -eu

# When true, re-own mounted folders so runtime user can read/write SQLite and logs.
MIGRATE_OWNERSHIP_ON_START="${MIGRATE_OWNERSHIP_ON_START:-true}"

fix_path_ownership_if_needed() {
    target_path="$1"

    if [ ! -e "$target_path" ]; then
        return
    fi

    if [ "$(id -u)" -ne 0 ]; then
        return
    fi

    if [ "$MIGRATE_OWNERSHIP_ON_START" != "true" ]; then
        return
    fi

    first_mismatch="$(find "$target_path" \( ! -user cyberbro -o ! -group cyberbro \) -print -quit)"
    if [ -z "$first_mismatch" ]; then
        return
    fi

    chown -R cyberbro:cyberbro "$target_path"
}

fix_path_ownership_if_needed "/app/data"
fix_path_ownership_if_needed "/var/log/cyberbro"
