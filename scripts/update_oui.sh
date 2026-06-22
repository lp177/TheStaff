#!/usr/bin/env bash
# Optional: refresh nmap's MAC-OUI vendor database before an event so newer
# device vendors fingerprint correctly. nmap ships a bundled list; this pulls
# the latest IEEE OUI registry and rebuilds nmap-mac-prefixes.
#
# Run on the HOST (or inside the container if it has internet during setup).
set -euo pipefail

PREFIXES="$(nmap --datadir /dev/null -V >/dev/null 2>&1; \
  for p in /usr/share/nmap /usr/local/share/nmap /opt/homebrew/share/nmap; do \
    [ -f "$p/nmap-mac-prefixes" ] && echo "$p/nmap-mac-prefixes" && break; done)"

if [ -z "${PREFIXES:-}" ]; then
  echo "!! Could not locate nmap-mac-prefixes; is nmap installed?" >&2
  exit 1
fi

echo ">> Updating $PREFIXES from IEEE…"
TMP="$(mktemp)"
curl -fsSL "https://standards-oui.ieee.org/oui/oui.txt" -o "$TMP"

# Convert IEEE "AABBCC   (base 16)   Vendor" lines to nmap's "AABBCC Vendor".
# IEEE oui.txt is CRLF — strip the carriage return first so vendor names don't
# end up with a trailing \r embedded in the nmap-mac-prefixes DB.
tr -d '\r' < "$TMP" | awk -F'\t' '/\(base 16\)/ {
  split($1, a, " "); prefix=a[1];
  vendor=$3; gsub(/^[ \t]+|[ \t]+$/, "", vendor);
  if (prefix != "" && vendor != "") print prefix" "vendor;
}' > "$PREFIXES.new"

if [ -s "$PREFIXES.new" ]; then
  mv "$PREFIXES.new" "$PREFIXES"
  echo ">> Updated $(wc -l < "$PREFIXES") OUI entries."
else
  echo "!! Parse produced no entries; leaving existing file untouched." >&2
  rm -f "$PREFIXES.new"
fi
rm -f "$TMP"
