#!/usr/bin/env bash
# Start the Mini SOC backend and frontend together for development.
# Run from the repository root in Git Bash (Windows) or any Linux/macOS shell:
#     bash automation/bash/start-dev.sh
# Press Ctrl+C once to stop both.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# The venv's python lives in Scripts/ on Windows and bin/ elsewhere.
if [[ -x "$ROOT/backend/.venv/Scripts/python.exe" ]]; then
  PY="$ROOT/backend/.venv/Scripts/python.exe"
elif [[ -x "$ROOT/backend/.venv/bin/python" ]]; then
  PY="$ROOT/backend/.venv/bin/python"
else
  echo "Backend virtual environment not found. See README.md (Quick start)." >&2
  exit 1
fi

if [[ ! -f "$ROOT/backend/.env" ]]; then
  echo "backend/.env is missing. Copy backend/.env.example and set SECRET_KEY." >&2
  exit 1
fi

cleanup() {
  echo "Stopping..."
  kill "${BACKEND_PID:-}" "${FRONTEND_PID:-}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

(cd "$ROOT/backend" && "$PY" -m uvicorn app.main:app --reload --port 8000) &
BACKEND_PID=$!

(cd "$ROOT/frontend" && npm run dev) &
FRONTEND_PID=$!

echo "Backend:  http://127.0.0.1:8000/docs"
echo "Frontend: http://localhost:5173"
wait
