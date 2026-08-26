#!/usr/bin/env bash
# Thin entrypoint: run whatever command the compose service specifies.
# With no arguments, drop into an interactive shell.
set -euo pipefail

if [ "$#" -eq 0 ]; then
    exec bash
fi
exec "$@"
