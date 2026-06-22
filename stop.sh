#!/usr/bin/env bash
# Stop (and remove) the running thestaff container.
#
#   ./stop.sh        # self-elevates with sudo if needed
#
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
  exec sudo -E "$ROOT/stop.sh" "$@"
fi

NAME="${NAME:-thestaff}"
# Also clean up the pre-rename "shieldmaster" container (one-time migration) so a
# leftover legacy container can't keep holding :8000 via --network=host.
stopped=0
for n in "$NAME" shieldmaster; do
  if podman container exists "$n" 2>/dev/null; then
    echo ">> Stopping $n…"
    podman stop "$n" >/dev/null 2>&1 || true
    podman rm -f "$n" >/dev/null 2>&1 || true   # run.sh uses --rm; clean up if it lingers
    stopped=1
  fi
done
[ "$stopped" = 1 ] && echo ">> Stopped." || echo ">> $NAME is not running — nothing to stop."
