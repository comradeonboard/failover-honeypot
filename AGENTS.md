# Base44 Dev Environment

## App Overview
Fullstack app: React (Vite) frontend in `frontend/` + FastAPI backend (`backend.py`). The backend monitors internet connectivity (pings 8.8.8.8 every 5s), detects failover to backup interfaces, runs an SSH honeypot on port 2222, and exposes a REST + WebSocket API. The React frontend is a monitoring dashboard with live status cards, uptime log, and honeypot alerts.

## Setup
- `docker compose -f docker-compose.base44.yml up -d --build`
- **frontend** (Vite dev server): node:22-slim, port 3000 (mapped from 5173), bind-mounted from `./frontend`, proxies `/api`, `/health`, `/ws` to the backend.
- **backend** (FastAPI + uvicorn --reload): built from the repo Dockerfile, port 8000, `backend.py` bind-mounted for live editing.

## Architecture
- Single origin: the React app is served at `/` by Vite; all API calls use relative paths (`/api/...`) which Vite proxies to the backend. The WebSocket at `/ws` is also proxied (`ws: true`).
- `VITE_BACKEND_URL=http://backend:8000` tells the Vite proxy where the backend lives inside the Docker network.

## Key Details
- API: `GET /api/status`, `GET /api/uptime-log`, `GET /api/honeypot-alerts` (includes `total_alerts`), `GET /health`, `WS /ws` (pushes full state every 2s).
- The honeypot binds port 2222 inside the backend container (not exposed to host).
- Backup interface check (usb0/wlan1/ppp0/teth0) always returns false in a container — expected; backup shows "Unavailable".
- No external credentials or secrets required.
- Frontend hot reload: Vite watches the bind-mounted `./frontend` (polling enabled via `CHOKIDAR_USEPOLLING=true`). Backend hot reload: uvicorn `--reload`.
- `frontend_node_modules` named volume keeps node_modules out of the bind mount so installs persist across restarts.

## Verification
- `curl http://localhost:3000/health` → `{"ok":true}` (proxied to backend)
- `curl http://localhost:3000/api/status` → connection status JSON
- `curl http://localhost:8000/api/status` → same, direct to backend
- Preview at port 3000 shows the React dashboard; the header indicator shows "Live" when the WebSocket connects.
