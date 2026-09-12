import subprocess
import time
import threading
from datetime import datetime
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import socket
import psutil
import logging
import asyncio

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class SystemMonitor:
    def __init__(self):
        self.primary_up = True
        self.backup_up = False
        self.active_connection = "primary"
        self.uptime_log = []
        self.honeypot_alerts = []
        
    def log_event(self, event_type, details):
        timestamp = datetime.now().isoformat()
        event = {"timestamp": timestamp, "type": event_type, "details": details}
        self.uptime_log.append(event)
        logger.info(f"{event_type}: {details}")
        
    def add_honeypot_alert(self, alert):
        alert["timestamp"] = datetime.now().isoformat()
        self.honeypot_alerts.append(alert)
        logger.warning(f"HONEYPOT ALERT: {alert}")

monitor = SystemMonitor()

def check_primary_connection():
    try:
        result = subprocess.run(["ping", "-c", "1", "8.8.8.8"], timeout=5, capture_output=True)
        return result.returncode == 0
    except:
        return False

def check_backup_connection():
    try:
        interfaces = psutil.net_if_addrs()
        for iface in ['usb0', 'wlan1', 'ppp0', 'teth0']:
            if iface in interfaces:
                return True
        return False
    except:
        return False

def monitor_connections():
    while True:
        primary = check_primary_connection()
        backup = check_backup_connection()
        if primary != monitor.primary_up:
            monitor.primary_up = primary
            if primary:
                monitor.log_event("PRIMARY_UP", "Online")
                monitor.active_connection = "primary"
            else:
                monitor.log_event("PRIMARY_DOWN", "Offline")
                if backup:
                    monitor.active_connection = "backup"
                    monitor.log_event("FAILOVER", "Backup active")
        if backup != monitor.backup_up:
            monitor.backup_up = backup
            status = "available" if backup else "unavailable"
            monitor.log_event("BACKUP_STATUS", status)
        time.sleep(5)

monitor_thread = threading.Thread(target=monitor_connections, daemon=True)
monitor_thread.start()

def start_ssh_honeypot():
    def handle_connection(client_socket, address):
        try:
            monitor.add_honeypot_alert({"type": "SSH_CONNECTION", "source_ip": address[0], "source_port": address[1]})
            client_socket.send(b"SSH-2.0-OpenSSH_7.4\r\n")
            data = client_socket.recv(1024)
            if data:
                monitor.add_honeypot_alert({"type": "SSH_BANNER", "source_ip": address[0]})
            client_socket.close()
        except:
            pass
    
    def honeypot_listener():
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('0.0.0.0', 2222))
            server.listen(5)
            logger.info("Honeypot on 2222")
            while True:
                client, address = server.accept()
                threading.Thread(target=handle_connection, args=(client, address), daemon=True).start()
        except:
            pass
    
    threading.Thread(target=honeypot_listener, daemon=True).start()

start_ssh_honeypot()

@app.get("/")
def root():
    return FileResponse("index.html")

@app.get("/api/status")
def get_status():
    return {"primary_up": monitor.primary_up, "backup_up": monitor.backup_up, "active": monitor.active_connection}

@app.get("/api/uptime-log")
def get_uptime_log():
    return {"events": monitor.uptime_log[-100:]}

@app.get("/api/honeypot-alerts")
def get_honeypot_alerts():
    return {"alerts": monitor.honeypot_alerts[-50:]}

@app.get("/health")
def health():
    return {"ok": True}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
