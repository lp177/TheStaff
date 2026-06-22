#!/usr/bin/env bash
# Build the thestaff container image (frontend is built inside the image).
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE="${IMAGE:-localhost/thestaff:latest}"

echo ">> Building $IMAGE with podman…"
podman build -t "$IMAGE" -f Containerfile .
echo ">> Done. Run it with: ./scripts/run.sh"
