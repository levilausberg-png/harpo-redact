#!/usr/bin/env bash
# Start Harpo, and your local model through Ollama, with one command. macOS and Linux.
#   ./boot.sh                            first run asks which provider; later runs just start
#   ./boot.sh --provider anthropic       also: --slm-model phi3:latest --no-slm --strict --pull --reconfigure --port N
set -eu
cd "$(dirname "$0")"
find_python() {
  for p in python3.13 python3.12 python3 python; do
    if command -v "$p" >/dev/null 2>&1 && "$p" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' 2>/dev/null; then
      echo "$p"
      return 0
    fi
  done
  return 1
}
mkdir -p .harpo
if [ ! -x .venv/bin/python ]; then
  if ! PY="$(find_python)"; then
    echo "  Python 3.12 or newer is required."
    if [ "$(uname -s)" = "Darwin" ]; then echo "  Install it with:  brew install python@3.12   (or from python.org)"
    else echo "  Install it with your package manager, e.g.:  sudo apt install python3.12 python3.12-venv"; fi
    exit 1
  fi
  echo "  First run: creating .venv (a private Python environment for the gateway)"
  "$PY" -m venv .venv || { echo "  Could not create .venv (Debian/Ubuntu: sudo apt install python3-venv)"; exit 1; }
fi
STAMP="$(.venv/bin/python -c 'import hashlib; print(hashlib.sha256(open("pyproject.toml", "rb").read()).hexdigest())')"
if [ "$(cat .harpo/install.stamp 2>/dev/null || true)" != "$STAMP" ]; then
  echo "  Installing Harpo into .venv (first run: 2-4 minutes)"
  .venv/bin/python -m pip install --disable-pip-version-check -q .
  echo "$STAMP" > .harpo/install.stamp
fi
exec .venv/bin/python -m harpo_redact up "$@"
