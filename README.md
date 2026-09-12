# Failover & Honeypot Monitor

Internet failover detection + SSH honeypot in one service.

## What It Does

- **Monitors internet**: Pings 8.8.8.8 every 5 seconds
- **Detects failover**: Switches to mobile hotspot backup if primary dies
- **Logs events**: All connection changes timestamped
- **Runs honeypot**: SSH service on port 2222 logs attackers
- **REST API**: Query status, logs, and alerts
- **WebSocket**: Real-time updates

## API Endpoints

- `GET /api/status` - Current connection status
- `GET /api/uptime-log` - Last 100 events
- `GET /api/honeypot-alerts` - Last 50 attack attempts
- `WS /ws` - WebSocket real-time feed
- `GET /health` - Health check

## Deploy on Render

1. Push this repo to GitHub
2. Go to https://dashboard.render.com
3. New → Web Service
4. Connect your failover-honeypot repo
5. Set Runtime: Docker
6. Deploy

Your app will be live at `https://failover-honeypot.onrender.com`

## Local Test

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python backend.py

Access at `http://localhost:8000/api/status`

## Configuration

Edit `backend.py`:
- Line 59: Change backup interfaces (usb0, wlan1, etc.)
- Line 80: Change monitor interval (default 5 seconds)
- Line 109: Change honeypot port (default 2222)

## Tech Stack

- FastAPI (Python)
- Async/await
- WebSocket
- Docker

## Author

Salem (@comradeonboard)
