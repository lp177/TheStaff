#!/usr/bin/env bash
# Local development (no container). Runs the backend in mock mode so you can
# work on the whole app with no network, nmap, or privileges.
#
#   ./scripts/dev.sh            # backend (mock) on :8000 with autoreload
#   then in another terminal:
#   cd frontend && npm install && npm run dev   # Vite on :5173 (proxies to :8000)
#
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -d .venv ]; then
  echo ">> Creating venv + installing backend deps…"
  python3 -m venv .venv
  .venv/bin/pip install --quiet --upgrade pip
  .venv/bin/pip install --quiet -r backend/requirements.txt
fi

export THESTAFF_MODE="${THESTAFF_MODE:-mock}"
export THESTAFF_DATA_DIR="${THESTAFF_DATA_DIR:-$PWD/data}"
export PYTHONPATH=.

echo ">> Backend (mode=$THESTAFF_MODE) on http://localhost:8000"
echo ">> Frontend: cd frontend && npm install && npm run dev  (http://localhost:5173)"
exec .venv/bin/uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
