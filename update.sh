#!/usr/bin/env bash
# Rebuild the image from the current source and restart the deployment.
#
#   ./update.sh                                  # rebuild + restart (auto-detect LAN)
#   sudo TARGET_CIDR=192.168.50.0/24 ./update.sh # rebuild + restart, pinned subnet
#
# NOTE: with sudo, pass vars INLINE as above. `export TARGET_CIDR=…; sudo ./update.sh`
# does NOT work — sudo's env_reset strips exported vars before this script starts.
# (Running as your user, `export TARGET_CIDR=…; ./update.sh`, does work — it uses sudo -E.)
#
# The image is ALWAYS built ROOTLESS (as your normal user). Building under rootful
# Podman has been observed to fail in `npm ci` ("Exit handler never called!" — it
# exits 0 and installs nothing, then `vite: not found`), likely due to memory/disk
# limits in root's image store. run.sh then syncs the rootless image into root
# storage (podman save | podman load), so only the container run needs root.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

# Load .env and require an operator token before building/deploying (fail fast).
# shellcheck disable=SC1091
. "$ROOT/scripts/load-env.sh"

build_rootless() { echo ">> [1/3] Rebuilding the image (rootless)…"; }

if [ "$(id -u)" -eq 0 ]; then
  # Invoked via sudo: build rootless as the original user, then run rootful here.
  if [ -z "${SUDO_USER:-}" ]; then
    echo "!! Don't run ./update.sh as the root user directly — rootful 'npm ci' is" >&2
    echo "   unreliable. Run it as your normal user (it elevates only for the run)." >&2
    exit 1
  fi
  build_rootless
  sudo -u "$SUDO_USER" "$ROOT/scripts/build.sh"
  echo ">> [2/3] Stopping the current container (if any)…"
  "$ROOT/stop.sh"
  echo ">> [3/3] Starting the rebuilt image (syncs rootless image into root storage)…"
  exec "$ROOT/scripts/run.sh" "$@"
else
  # Invoked as your user: build rootless, then elevate only for stop + run.
  build_rootless
  "$ROOT/scripts/build.sh"
  echo ">> [2/3] Stopping the current container (if any)…"
  sudo -E "$ROOT/stop.sh"
  echo ">> [3/3] Starting the rebuilt image (syncs rootless image into root storage)…"
  exec sudo -E "$ROOT/scripts/run.sh" "$@"
fi
