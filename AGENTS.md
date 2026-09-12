# Base44 Dev Environment

## App Overview
FastAPI backend (`backend.py`) that monitors internet connectivity (pings 8.8.8.8 every 5s), detects failover to backup interfaces, runs an SSH honeypot on port 2222, and serves a single-page frontend (`index.html`) at `/`.

## Setup
- `docker compose -f docker-compose.base44.yml up -d --build`
- The compose builds from the repo's `Dockerfile` (installs iputils-ping, net-tools, pip deps), then bind-mounts the source and runs uvicorn with `--reload` so edits appear live.
- Web entry point is on host port **3000** (mapped to container port 8000).

## Key Details
- The root route `/` serves `index.html` via `FileResponse`. The frontend fetches API endpoints from the same origin (`window.location.origin`).
- API endpoints: `/api/status`, `/api/uptime-log`, `/api/honeypot-alerts`, `/health`, WS `/ws`.
- No external credentials or secrets required — the app is fully self-contained.
- The honeypot binds port 2222 inside the container (not exposed to host).
- `psutil` is used to check for backup network interfaces (usb0, wlan1, ppp0, teth0) — these won't exist in the container, so backup status will always show "Unavailable" (expected in this environment).

## Verification
- `curl http://localhost:3000/health` → `{"ok":true}`
- `curl http://localhost:3000/api/status` → connection status JSON
- Preview at port 3000 shows the dashboard UI.
