# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# thestaff — consent-based WiFi security-awareness game
# Multi-stage build: build the Vue SPA, then assemble the scanner runtime.
# ---------------------------------------------------------------------------

# 1) Build the frontend
FROM node:20-alpine AS frontend
# Disable npm's audit/fund/update-notifier: they make network calls and run at
# process exit, which has been seen to trip npm's "Exit handler never called!"
# race (npm prints it, exits 0, and installs *nothing*). CI=true keeps it quiet.
ENV CI=true \
    NPM_CONFIG_AUDIT=false \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_UPDATE_NOTIFIER=false
WORKDIR /fe
COPY frontend/package.json frontend/package-lock.json ./
# Honor the committed lockfile (reproducible build) and FAIL LOUDLY if the install
# silently no-ops — otherwise the next stage dies with a confusing "vite: not found".
RUN npm ci && test -x node_modules/.bin/vite
COPY frontend/ ./
RUN npm run build

# 2) Runtime: nmap + NSE + python backend + built SPA
FROM python:3.12-alpine

# nmap + the NSE scripts dir + iproute2 (for `ip route`, gateway detection) + git
RUN apk add --no-cache nmap nmap-scripts iproute2 git ca-certificates

# External NSE: vulners (online CVE lookups) + vulscan (offline CSV databases).
# Pin to reviewed commit SHAs for a reproducible, supply-chain-safe build:
#   podman build --build-arg VULNERS_REF=<sha> --build-arg VULSCAN_REF=<sha> ...
ARG VULNERS_REF=master
ARG VULSCAN_REF=master
RUN git clone https://github.com/vulnersCom/nmap-vulners.git \
        /usr/share/nmap/scripts/nmap-vulners && \
    git -C /usr/share/nmap/scripts/nmap-vulners checkout "$VULNERS_REF" && \
    git clone https://github.com/scipag/vulscan.git \
        /usr/share/nmap/scripts/vulscan && \
    git -C /usr/share/nmap/scripts/vulscan checkout "$VULSCAN_REF" && \
    cp /usr/share/nmap/scripts/nmap-vulners/*.nse /usr/share/nmap/scripts/ && \
    cp /usr/share/nmap/scripts/vulscan/*.nse /usr/share/nmap/scripts/ && \
    nmap --script-updatedb || true

# Python deps in a venv.
COPY backend/requirements.txt /tmp/requirements.txt
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt
ENV PATH="/opt/venv/bin:${PATH}" \
    THESTAFF_MODE=real \
    THESTAFF_DATA_DIR=/data \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY backend /app/backend
COPY --from=frontend /fe/dist /app/frontend/dist

# Runs as root INSIDE the (rootful) container so nmap keeps EFFECTIVE CAP_NET_RAW
# — a non-root uid would lose the cap across exec and -sS/-O/-PR would fail. The
# container itself is locked down by the runtime: --cap-drop=ALL except NET_RAW,
# --read-only, --security-opt=no-new-privileges (see scripts/run.sh & deploy/).
RUN mkdir -p /data

VOLUME ["/data"]
EXPOSE 8000

ENTRYPOINT ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
