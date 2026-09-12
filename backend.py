import subprocess
import time
import threading
import socket
from datetime import datetime
from fastapi import FastAPI, WebSocket, HTTPException
from fastapi.middleware.cors import CORSMiddleware
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
        if len(self.honeypot_alerts) > 500:
            self.honeypot_alerts = self.honeypot_alerts[-500:]
        logger.warning(f"HONEYPOT ALERT: {alert}")

monitor = SystemMonitor()
monitor.log_event("MONITOR_START", "Monitoring service started")

# ============ CONNECTIVITY MONITORING ============

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

# ============ HONEYPOT SYSTEM ============

class HoneypotService:
    def __init__(self, name, port, protocol):
        self.name = name
        self.port = port
        self.protocol = protocol
        self.enabled = False
        self.running = False
        self.total_connections = 0
        self.unique_ips = set()
        self.last_attack = None
        self.server_socket = None

    def to_dict(self):
        return {
            "name": self.name,
            "port": self.port,
            "protocol": self.protocol,
            "enabled": self.enabled,
            "running": self.running,
            "total_connections": self.total_connections,
            "unique_ips": len(self.unique_ips),
            "last_attack": self.last_attack,
        }

class HoneypotManager:
    def __init__(self, monitor):
        self.monitor = monitor
        self.services = {}

    def register(self, name, port, protocol, handler):
        service = HoneypotService(name, port, protocol)
        self.services[name] = {"service": service, "handler": handler, "thread": None}
        return service

    def start(self, name):
        entry = self.services.get(name)
        if not entry:
            return
        service = entry["service"]
        if service.running or service.enabled:
            return
        service.enabled = True

        def listener():
            server = None
            try:
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind(('0.0.0.0', service.port))
                server.listen(5)
                server.settimeout(1.0)
                service.server_socket = server
                service.running = True
                logger.info(f"Honeypot '{service.name}' listening on port {service.port}")
                while service.running:
                    try:
                        client, address = server.accept()
                        service.total_connections += 1
                        service.unique_ips.add(address[0])
                        service.last_attack = datetime.now().isoformat()
                        threading.Thread(
                            target=entry["handler"],
                            args=(client, address, service),
                            daemon=True
                        ).start()
                    except socket.timeout:
                        continue
                    except OSError:
                        break
            except Exception as e:
                logger.error(f"Honeypot '{name}' failed on port {service.port}: {e}")
                service.enabled = False
            finally:
                service.running = False
                if server:
                    try:
                        server.close()
                    except:
                        pass

        thread = threading.Thread(target=listener, daemon=True)
        entry["thread"] = thread
        thread.start()

    def stop(self, name):
        entry = self.services.get(name)
        if not entry:
            return
        service = entry["service"]
        service.enabled = False
        service.running = False
        if service.server_socket:
            try:
                service.server_socket.close()
            except:
                pass
            service.server_socket = None
        thread = entry.get("thread")
        if thread and thread.is_alive():
            thread.join(timeout=2)
        logger.info(f"Honeypot '{name}' stopped")


# ============ HONEYPOT HANDLERS ============

def ssh_handler(client, address, service):
    """SSH honeypot - captures SSH banners and initial packets."""
    try:
        client.send(b"SSH-2.0-OpenSSH_7.4\r\n")
        monitor.add_honeypot_alert({
            "type": "SSH_CONNECTION",
            "source_ip": address[0],
            "source_port": address[1],
            "service": service.name,
            "severity": "medium",
        })
        client.settimeout(5)
        try:
            data = client.recv(1024)
            if data:
                banner = data.decode('utf-8', errors='replace').strip()[:200]
                monitor.add_honeypot_alert({
                    "type": "SSH_BANNER",
                    "source_ip": address[0],
                    "data": banner,
                    "service": service.name,
                    "severity": "low",
                })
        except socket.timeout:
            pass
    except:
        pass
    finally:
        try:
            client.close()
        except:
            pass

def http_handler(client, address, service):
    """HTTP honeypot - captures HTTP requests, serves a fake admin login page."""
    try:
        client.settimeout(5)
        data = client.recv(4096)
        if not data:
            return
        request = data.decode('utf-8', errors='replace')
        request_line = request.split('\n')[0].strip()[:200]
        monitor.add_honeypot_alert({
            "type": "HTTP_REQUEST",
            "source_ip": address[0],
            "source_port": address[1],
            "data": request_line,
            "service": service.name,
            "severity": "low",
        })
        if request_line.startswith('POST'):
            monitor.add_honeypot_alert({
                "type": "HTTP_LOGIN_ATTEMPT",
                "source_ip": address[0],
                "data": request_line,
                "service": service.name,
                "severity": "high",
            })
        body = b"<html><head><title>Admin Panel</title></head><body><h1>Admin Login</h1><form method='POST'><input name='username' placeholder='Username'><input name='password' type='password' placeholder='Password'><button>Login</button></form></body></html>"
        response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body
        client.send(response)
    except:
        pass
    finally:
        try:
            client.close()
        except:
            pass

def ftp_handler(client, address, service):
    """FTP honeypot - captures FTP usernames and passwords."""
    try:
        client.send(b"220 FTP Server Ready\r\n")
        monitor.add_honeypot_alert({
            "type": "FTP_CONNECTION",
            "source_ip": address[0],
            "source_port": address[1],
            "service": service.name,
            "severity": "medium",
        })
        client.settimeout(10)
        username = None
        buffer = ""
        while True:
            data = client.recv(1024)
            if not data:
                break
            buffer += data.decode('utf-8', errors='replace')
            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                command = line.strip()
                if not command:
                    continue
                upper = command.upper()
                if upper.startswith('USER'):
                    username = command.split(' ', 1)[1] if ' ' in command else ''
                    monitor.add_honeypot_alert({
                        "type": "FTP_USER",
                        "source_ip": address[0],
                        "data": f"USER: {str(username)[:100]}",
                        "service": service.name,
                        "severity": "medium",
                    })
                    client.send(b"331 Password required\r\n")
                elif upper.startswith('PASS'):
                    password = command.split(' ', 1)[1] if ' ' in command else ''
                    monitor.add_honeypot_alert({
                        "type": "FTP_CREDENTIALS",
                        "source_ip": address[0],
                        "data": f"USER: {str(username)[:50]} | PASS: {password[:50]}",
                        "service": service.name,
                        "severity": "high",
                    })
                    client.send(b"530 Login incorrect\r\n")
                elif upper.startswith('QUIT'):
                    return
                else:
                    client.send(b"530 Not logged in\r\n")
    except:
        pass
    finally:
        try:
            client.close()
        except:
            pass

def telnet_handler(client, address, service):
    """Telnet honeypot - captures telnet login attempts."""
    try:
        monitor.add_honeypot_alert({
            "type": "TELNET_CONNECTION",
            "source_ip": address[0],
            "source_port": address[1],
            "service": service.name,
            "severity": "medium",
        })
        client.send(b"Welcome to Router Console\r\nlogin: ")
        client.settimeout(10)
        data = client.recv(4096)
        if not data:
            return
        lines = data.decode('utf-8', errors='replace').strip().split('\n')
        login = lines[0].strip()[:100] if lines else ""
        monitor.add_honeypot_alert({
            "type": "TELNET_LOGIN",
            "source_ip": address[0],
            "data": f"LOGIN: {login}",
            "service": service.name,
            "severity": "high",
        })
        if len(lines) > 1:
            password = lines[1].strip()[:100]
        else:
            client.send(b"Password: ")
            try:
                data = client.recv(1024)
                password = data.decode('utf-8', errors='replace').strip()[:100] if data else ""
            except socket.timeout:
                password = ""
        if password:
            monitor.add_honeypot_alert({
                "type": "TELNET_CREDENTIALS",
                "source_ip": address[0],
                "data": f"LOGIN: {login[:50]} | PASS: {password[:50]}",
                "service": service.name,
                "severity": "high",
            })
        client.send(b"Login incorrect\r\n")
    except:
        pass
    finally:
        try:
            client.close()
        except:
            pass


# ============ HONEYPOT INITIALIZATION ============

honeypot_manager = HoneypotManager(monitor)
honeypot_manager.register("ssh", 2222, "TCP", ssh_handler)
honeypot_manager.register("http", 8080, "TCP", http_handler)
honeypot_manager.register("ftp", 2121, "TCP", ftp_handler)
honeypot_manager.register("telnet", 2323, "TCP", telnet_handler)

for name in honeypot_manager.services:
    honeypot_manager.start(name)


def compute_attack_stats():
    alerts = monitor.honeypot_alerts
    ip_counts = {}
    severity_counts = {"low": 0, "medium": 0, "high": 0}
    service_counts = {}
    for a in alerts:
        ip = a.get("source_ip", "unknown")
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
        severity = a.get("severity", "low")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        service = a.get("service", "unknown")
        service_counts[service] = service_counts.get(service, 0) + 1
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    return {
        "total_alerts": len(alerts),
        "top_attacker_ips": [{"ip": ip, "count": count} for ip, count in top_ips],
        "severity_breakdown": severity_counts,
        "service_breakdown": service_counts,
    }


# ============ API ROUTES ============

@app.get("/")
def root():
    return {"status": "ok", "message": "Failover Monitor Running"}

@app.get("/api/status")
def get_status():
    return {"primary_up": monitor.primary_up, "backup_up": monitor.backup_up, "active": monitor.active_connection}

@app.get("/api/uptime-log")
def get_uptime_log():
    return {"events": monitor.uptime_log[-100:]}

@app.get("/api/honeypot-alerts")
def get_honeypot_alerts():
    return {"alerts": monitor.honeypot_alerts[-50:], "total_alerts": len(monitor.honeypot_alerts)}

@app.get("/api/honeypot/services")
def get_honeypot_services():
    return {"services": [s["service"].to_dict() for s in honeypot_manager.services.values()]}

@app.post("/api/honeypot/toggle/{service_name}")
def toggle_honeypot(service_name: str):
    entry = honeypot_manager.services.get(service_name)
    if not entry:
        raise HTTPException(status_code=404, detail=f"Service '{service_name}' not found")
    service = entry["service"]
    if service.enabled:
        honeypot_manager.stop(service_name)
        return {"name": service_name, "enabled": False, "running": False}
    else:
        honeypot_manager.start(service_name)
        return {"name": service_name, "enabled": True, "running": True}

@app.post("/api/honeypot/clear")
def clear_alerts():
    monitor.honeypot_alerts = []
    logger.info("Honeypot alerts cleared")
    return {"ok": True, "cleared": True}

@app.get("/api/honeypot/stats")
def get_honeypot_stats():
    return compute_attack_stats()

@app.get("/health")
def health():
    return {"ok": True}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            data = {
                "status": {
                    "primary_up": monitor.primary_up,
                    "backup_up": monitor.backup_up,
                    "active": monitor.active_connection,
                },
                "uptime_log": monitor.uptime_log[-100:],
                "honeypot_alerts": monitor.honeypot_alerts[-50:],
                "total_alerts": len(monitor.honeypot_alerts),
                "honeypot_services": [s["service"].to_dict() for s in honeypot_manager.services.values()],
                "attack_stats": compute_attack_stats(),
            }
            await websocket.send_json(data)
            await asyncio.sleep(2)
    except Exception:
        pass

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
