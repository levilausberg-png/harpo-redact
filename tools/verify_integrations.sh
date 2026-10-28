#!/usr/bin/env bash
# Run every example against a demo gateway and check that no raw value reached the (fake) provider.
set -euo pipefail
cd "$(dirname "$0")/.."
export HARPO_URL=${HARPO_URL:-http://127.0.0.1:8080}
out=$(mktemp)
for f in examples/python/*.py; do echo "== $f"; python "$f" | tee -a "$out"; done
(cd examples/node && npm install --silent --no-audit --no-fund >/dev/null && for f in *.mjs; do echo "== $f"; node "$f" | tee -a "$out"; done)
# The fake provider echoes what it received: the raw values must not be in it.
if grep -E "jane\.doe@acme\.com|4111 1111 1111 1111|NL91ABNA0417164300|priya|bob@corp\.example|\+31 20 794 6095" -i "$out"; then
  echo "FAIL: a raw value reached the provider"; exit 1
fi
echo "OK: every client works through the gateway and no raw value reached the provider"
