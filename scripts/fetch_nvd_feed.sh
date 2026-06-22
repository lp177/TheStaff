#!/usr/bin/env bash
# Pre-event: snapshot the offline CVE enrichment feed (fkie-cad/nvd-json-data-feeds)
# into data/nvd so CVE descriptions/CVSS/references work without internet.
#
# This is OPTIONAL — thestaff runs fine without it (it falls back to the
# CVSS/refs that vulners/vulscan provide). Recommended for venues with no wifi.
#
#   ./scripts/fetch_nvd_feed.sh 2023 2024 2025
#
set -euo pipefail
cd "$(dirname "$0")/.."

YEARS=("$@")
[ ${#YEARS[@]} -eq 0 ] && YEARS=(2022 2023 2024 2025)

DEST="data/nvd"
REPO="https://github.com/fkie-cad/nvd-json-data-feeds.git"
mkdir -p "$DEST"

TMP="$(mktemp -d)"
echo ">> Sparse-cloning ${YEARS[*]} from $REPO…"
git clone --depth=1 --filter=blob:none --sparse "$REPO" "$TMP"
( cd "$TMP" && git sparse-checkout set "${YEARS[@]/#/CVE-}" )

for y in "${YEARS[@]}"; do
  if [ -d "$TMP/CVE-$y" ]; then
    echo ">> Copying CVE-$y…"
    cp -r "$TMP/CVE-$y" "$DEST/"
  else
    echo "!! CVE-$y not found in feed (skipping)"
  fi
done

rm -rf "$TMP"
echo ">> Offline NVD feed ready in $DEST (restart thestaff to load it)."
