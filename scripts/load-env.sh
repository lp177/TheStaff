#!/usr/bin/env bash
# Sourced (not executed) by run.sh / start.sh / update.sh.
# Loads the gitignored project .env and REQUIRES an operator token so a real
# deployment never runs wide open. Generate a token with: openssl rand -hex 24
# shellcheck shell=bash
__envroot="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ -f "$__envroot/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$__envroot/.env"
  set +a
fi

if [ -z "${THESTAFF_ADMIN_TOKEN:-}" ]; then
  echo "!! Missing operator token (THESTAFF_ADMIN_TOKEN) in $__envroot/.env" >&2
  echo "   Create it once (the file is gitignored):" >&2
  echo "     cp .env.example .env" >&2
  echo "     sed -i \"s|^THESTAFF_ADMIN_TOKEN=.*|THESTAFF_ADMIN_TOKEN=\$(openssl rand -hex 24)|\" .env" >&2
  echo "   Then enter the SAME token in the dashboard: Settings (gear) -> Operator token." >&2
  exit 1
fi
unset __envroot
