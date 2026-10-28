#!/usr/bin/env bash
# Stop what boot.sh started: the gateway, the local model in memory, and Ollama if boot started it.
#   ./stop.sh            also: --keep-ollama --keep-model
set -eu
cd "$(dirname "$0")"
if [ ! -x .venv/bin/python ]; then echo "  Nothing to stop: boot.sh has not run in this folder."; exit 0; fi
exec .venv/bin/python -m harpo_redact down "$@"
