#!/usr/bin/env bash
# Run thestaff in rootful Podman with host networking + the single
# capability nmap needs (CAP_NET_RAW). Never uses --privileged.
#
# Usage:
#   sudo TARGET_CIDR=192.168.50.0/24 ./scripts/run.sh
#
set -euo pipefail
cd "$(dirname "$0")/.."

# Load .env and require an operator token (THESTAFF_ADMIN_TOKEN) before deploying.
# shellcheck disable=SC1091
. "$(dirname "$0")/load-env.sh"

IMAGE="${IMAGE:-localhost/thestaff:latest}"
# "auto" => the app detects the LAN subnet from the host's interfaces.
TARGET_CIDR="${TARGET_CIDR:-auto}"
SCAN_INTERVAL_MIN="${SCAN_INTERVAL_MIN:-15}"
ORGANIZER="${THESTAFF_ORGANIZER:-the event team}"
SSID="${THESTAFF_SSID:-thestaff-challenge}"
DATA_DIR="${DATA_DIR:-$PWD/data}"

mkdir -p "$DATA_DIR"

if [ "$(id -u)" -ne 0 ]; then
  echo "!! Rootful Podman is required (raw sockets for ARP/-sS/-O are blocked"
  echo "   for rootless containers). Re-run with: sudo $0" >&2
  exit 1
fi

# The container runs as root with ALL caps dropped except NET_RAW. Without
# CAP_DAC_OVERRIDE, in-container root must actually OWN the data bind mount to
# create the DB / scan files, so make uid 0 the owner (rootful: container
# root == host root). Without this the app can't write /data and exits at boot.
chown -R 0:0 "$DATA_DIR"

# Rootful and rootless Podman keep SEPARATE image stores. If you build rootless
# (./scripts/build.sh) and run rootful (sudo), sync the build into root's store —
# AND re-sync whenever the rootless image is newer (different ID), so rebuilds
# actually take effect instead of silently running a stale image.
ROOTLESS_ID=""
if [ -n "${SUDO_USER:-}" ] && sudo -u "$SUDO_USER" podman image exists "$IMAGE" 2>/dev/null; then
  ROOTLESS_ID=$(sudo -u "$SUDO_USER" podman image inspect -f '{{.Id}}' "$IMAGE" 2>/dev/null || true)
fi
ROOT_ID=$(podman image inspect -f '{{.Id}}' "$IMAGE" 2>/dev/null || true)

if [ -n "$ROOTLESS_ID" ] && [ "$ROOTLESS_ID" != "$ROOT_ID" ]; then
  echo ">> Syncing image from ${SUDO_USER}'s rootless build into root storage…"
  sudo -u "$SUDO_USER" podman save "$IMAGE" | podman load
elif [ -z "$ROOT_ID" ] && [ -z "$ROOTLESS_ID" ]; then
  echo "!! Image '$IMAGE' not found in root or ${SUDO_USER:-your} Podman storage." >&2
  echo "   Build it first:  ./scripts/build.sh" >&2
  exit 1
elif [ -n "$ROOT_ID" ] && [ -z "$ROOTLESS_ID" ]; then
  # Couldn't read a rootless image (no SUDO_USER, or the rootless lookup failed),
  # but a root image exists — run it, and make clear it may be an older build.
  echo "!! Could not read a rootless '$IMAGE'; running the existing image in root" >&2
  echo "   storage — it may be STALE. Rebuild with ./update.sh if you expected changes." >&2
fi

if [ "$TARGET_CIDR" = "auto" ]; then
  echo ">> Auto-detecting the LAN to scan (override with TARGET_CIDR=…). UI at http://<host>:8000"
else
  echo ">> Scanning $TARGET_CIDR every ${SCAN_INTERVAL_MIN}m. UI at http://<host>:8000"
fi

# --pull=never: fail clearly if the image is missing rather than hitting a registry.
RUN_ARGS=(
  --rm -d
  --replace
  --name thestaff
  --network=host
  --cap-drop=ALL
  --cap-add=NET_RAW
  --security-opt=no-new-privileges
  --read-only
  --tmpfs /tmp:rw,nosuid,nodev,size=64m
  --pull=never
  -e PYTHONDONTWRITEBYTECODE=1
  -e THESTAFF_MODE=real
  -e TARGET_CIDR="$TARGET_CIDR"
  -e SCAN_INTERVAL_MIN="$SCAN_INTERVAL_MIN"
  -e THESTAFF_ORGANIZER="$ORGANIZER"
  -e THESTAFF_SSID="$SSID"
  -e THESTAFF_CONSENT_MODE="${THESTAFF_CONSENT_MODE:-wifi}"
  -v "$DATA_DIR":/data:Z
)
[ -n "${THESTAFF_ADMIN_TOKEN:-}" ] && RUN_ARGS+=(-e THESTAFF_ADMIN_TOKEN="$THESTAFF_ADMIN_TOKEN")

# One-time migration: drop the pre-rename container so it frees the host port
# (--replace only replaces our own --name; --network=host means a leftover
# "shieldmaster" would still hold :8000 and the run below would fail to bind).
podman rm -f shieldmaster >/dev/null 2>&1 || true

podman run "${RUN_ARGS[@]}" "$IMAGE"
echo ">> Started. Logs: sudo podman logs -f thestaff   |   Stop: sudo podman stop thestaff"
