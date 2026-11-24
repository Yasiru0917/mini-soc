"""Pull new Wazuh alerts from the command line (automation).

Usage (backend folder, venv active):
    python -m scripts.wazuh_sync               # one sync, then exit
    python -m scripts.wazuh_sync --interval 300 # keep syncing every 5 minutes (Ctrl+C to stop)

Useful with Windows Task Scheduler or cron so alerts arrive without
anyone pressing "Sync" in the UI.
"""

import argparse
import sys
import time

from app.db.migrate import upgrade_database
from app.db.session import SessionLocal
from app.integrations.wazuh.client import WazuhError
from app.services import wazuh_sync


def run_once() -> bool:
    with SessionLocal() as db:
        try:
            r = wazuh_sync.sync_alerts(db)
        except WazuhError as exc:
            print(f"[wazuh-sync] ERROR: {exc}", file=sys.stderr)
            return False
    print(f"[wazuh-sync] fetched={r['fetched']} created={r['created']} duplicates={r['duplicates']} "
          f"cursor={r['cursor']}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Import Wazuh alerts into Mini SOC")
    parser.add_argument("--interval", type=int, default=0, help="seconds between syncs (0 = run once)")
    args = parser.parse_args()
    upgrade_database()
    if args.interval <= 0:
        return 0 if run_once() else 1
    if args.interval < 30:
        parser.error("--interval must be at least 30 seconds")
    while True:
        run_once()
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
