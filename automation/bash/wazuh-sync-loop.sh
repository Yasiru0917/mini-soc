#!/usr/bin/env bash
# Keep importing Wazuh alerts every N seconds (default 300).
#     bash automation/bash/wazuh-sync-loop.sh [seconds]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INTERVAL="${1:-300}"
[[ "$INTERVAL" =~ ^[0-9]+$ ]] || { echo "Interval must be a number of seconds" >&2; exit 1; }

if [[ -x "$ROOT/backend/.venv/Scripts/python.exe" ]]; then PY="$ROOT/backend/.venv/Scripts/python.exe"
else PY="$ROOT/backend/.venv/bin/python"; fi

cd "$ROOT/backend"
exec "$PY" -m scripts.wazuh_sync --interval "$INTERVAL"
