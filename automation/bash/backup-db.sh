#!/usr/bin/env bash
# Make a consistent, timestamped backup of the Mini SOC SQLite database.
#     bash automation/bash/backup-db.sh [backup-folder]
#
# Uses SQLite's online backup API (through Python) rather than copying the
# file, so the backup is consistent even while the server is writing to it.
# Backups contain sensitive security data: keep them private, never commit them.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DB="$ROOT/backend/data/soc.db"
DEST="${1:-$ROOT/backend/data/backups}"
KEEP=10   # number of backups to keep

if [[ -x "$ROOT/backend/.venv/Scripts/python.exe" ]]; then PY="$ROOT/backend/.venv/Scripts/python.exe"
else PY="$ROOT/backend/.venv/bin/python"; fi

[[ -f "$DB" ]] || { echo "Database not found: $DB" >&2; exit 1; }
mkdir -p "$DEST"
OUT="$DEST/soc-$(date -u +%Y%m%dT%H%M%SZ).db"

"$PY" - "$DB" "$OUT" <<'PY'
import sqlite3, sys
src, dst = sqlite3.connect(sys.argv[1]), sqlite3.connect(sys.argv[2])
with dst:
    src.backup(dst)
ok = dst.execute("PRAGMA integrity_check").fetchone()[0]
src.close(); dst.close()
if ok != "ok":
    sys.exit(f"Integrity check failed: {ok}")
PY

echo "Backup written: $OUT"

# Rotate: delete all but the newest $KEEP backups.
ls -1t "$DEST"/soc-*.db 2>/dev/null | tail -n +$((KEEP + 1)) | while read -r old; do
  rm -f -- "$old" && echo "Removed old backup: $old"
done
