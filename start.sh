#!/usr/bin/env bash
# Start thestaff locally in rootful Podman (host net + CAP_NET_RAW).
#
# Thin wrapper around scripts/run.sh that also builds the image first if it's
# missing, and self-elevates with sudo (rootful Podman is required — rootless
# can't open the raw sockets nmap needs). Env/args pass straight through, e.g.:
#
#   ./start.sh                                  # auto-detect the LAN, real mode
#   sudo TARGET_CIDR=192.168.50.0/24 ./start.sh # pin the subnet
#
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

# Load .env and require an operator token before doing anything (fail fast).
# shellcheck disable=SC1091
. "$ROOT/scripts/load-env.sh"

# Rootful Podman required → re-exec under sudo, preserving the environment.
if [ "$(id -u)" -ne 0 ]; then
  echo ">> thestaff needs rootful Podman; re-running with sudo…"
  exec sudo -E "$ROOT/start.sh" "$@"
fi

IMAGE="${IMAGE:-localhost/thestaff:latest}"

# Build only if the image is absent from BOTH stores (run.sh syncs a rootless
# build into root storage on its own; we just cover the truly-missing case).
if ! podman image exists "$IMAGE"; then
  rootless_has=no
  if [ -n "${SUDO_USER:-}" ] && sudo -u "$SUDO_USER" podman image exists "$IMAGE" 2>/dev/null; then
    rootless_has=yes
  fi
  if [ "$rootless_has" = no ]; then
    # Build ROOTLESS (rootful 'npm ci' is unreliable). run.sh then syncs it into
    # root storage. Build as the invoking user when we got here via sudo.
    if [ -n "${SUDO_USER:-}" ]; then
      echo ">> Image '$IMAGE' not found — building it first (rootless, as $SUDO_USER)…"
      sudo -u "$SUDO_USER" "$ROOT/scripts/build.sh"
    else
      echo ">> Image '$IMAGE' not found — building it first…"
      "$ROOT/scripts/build.sh"
    fi
  fi
fi

exec "$ROOT/scripts/run.sh" "$@"
