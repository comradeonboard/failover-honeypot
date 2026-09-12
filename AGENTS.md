# Base44 Dev Environment

## App Overview
Fullstack security monitoring console: React (Vite) frontend in `frontend/` + FastAPI backend (`backend.py`) + 3 attacker-bot containers (`attacker/bot.py`). The backend monitors internet connectivity, runs 4 honeypots (SSH/HTTP/FTP/Telnet) with SQLite-persisted captures (`backend_data` volume, `/app/data/honeypot.db`), sweeps the local /24 subnet for connected devices, and exposes REST + WebSocket APIs. The attacker bots are separate containers with their own IPs that continuously attack the honeypots (SSH banner grabs, HTTP credential stuffing, FTP/Telnet brute-force) — the honeypots capture these as real sessions. Frontend is a dark tactical ops-console UI (no emojis, monospace uppercase).

## Setup
- `docker compose -f docker-compose.base44.yml up -d --build`
- **frontend** (Vite dev server): node:22-slim, host port 3000 (container 5173), bind-mounted from `./frontend`, proxies `/api`, `/health`, `/ws` to the backend.
- **backend** (FastAPI + uvicorn --reload): built from repo Dockerfile, host ports 8000 (API) + 2222/8080/2121/2323 (honeypots). `backend.py` bind-mounted for live editing.

## Architecture
- Single origin: Vite serves the React app at `/`; relative API paths are proxied (`ws: true` for the WebSocket).
- `VITE_BACKEND_URL=http://backend:8000` points the Vite proxy at the backend inside the Docker network.
- NOTE: uvicorn's file watcher sometimes misses bind-mounted changes — if new backend routes 404, `docker compose -f docker-compose.base44.yml restart backend`.

## Key Details
- API: `GET /api/status`, `/api/uptime-log`, `/api/honeypot-alerts` (with `total_alerts`), `/api/honeypot/services`, `/api/honeypot/stats`, `/api/network/devices`; `POST /api/honeypot/toggle/{name}`, `/api/honeypot/clear`, `/api/network/scan`; `WS /ws` pushes full state every 2s.
- Honeypots: 4 independent TCP listeners (HoneypotManager), start/stop at runtime, capture banners/credentials, severity-scored alerts. Alerts persist to SQLite (AlertStore) and survive backend restarts; in-memory list capped at 500. "Clear Alerts" wipes both memory and DB. Per-service hit counters are runtime-only (reset on restart).
- Attacker bots: 3 compose services (attacker-1/2/3) running attacker/bot.py; each attacks a random honeypot every 4-15s. Deleting a bot = less traffic; scale by adding services.
- Network scanner: ping-sweeps the local /24 (64 threads), resolves hostname via gethostbyaddr, MAC from /proc/net/arp. Auto-scans on startup; manual re-scan via POST /api/network/scan.
- Auth: single console user (comradeonboard), password stored as SHA-256 hash in backend.py (AUTH_PASSWORD_HASH). POST /api/auth/login issues a random session token; HTTP middleware gates all /api/* except /api/auth/login; WS requires ?token=. Sessions are in-memory — a backend restart invalidates them and the frontend auto-returns to the login page. Frontend stores token in localStorage ('fhm_token'), Login.jsx gates App, Dashboard.jsx holds the console UI, logout button in Header.
- Honeypot state is in-memory — resets on backend restart (expected).
- Backup interface check (usb0/wlan1/ppp0/teth0) always false in a container — expected.
- No external credentials or secrets required.
- Frontend hot reload: Vite watches the bind mount (CHOKIDAR_USEPOLLING=true). node_modules kept in the `frontend_node_modules` named volume.

## Verification
- `curl http://localhost:3000/health` → `{"ok":true}`
- `curl http://localhost:3000/api/network/devices` → scanner state + device list
- Attack a honeypot: `printf "USER root\r\nPASS toor\r\nQUIT\r\n" | nc -w 2 localhost 2121` then check `/api/honeypot-alerts`
- Preview at port 3000: dark console, "Link Active" indicator when WS connects.
