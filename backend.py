import subprocess
import time
import threading
import socket
import concurrent.futures
import sqlite3
import os
import hashlib
import secrets
from datetime import datetime
from fastapi import FastAPI, WebSocket, HTTPException, Request
from fastapi.responses import JSONResponse
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

# ============ ALERT PERSISTENCE ============

DB_PATH = os.environ.get("HONEYPOT_DB", "/app/data/honeypot.db")

class AlertStore:
    """Persists honeypot alerts to SQLite so captures survive restarts."""

    def __init__(self, path=DB_PATH):
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
        except OSError:
            path = "honeypot.db"
        self.path = path
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                type TEXT NOT NULL,
                source_ip TEXT,
                source_port INTEGER,
                service TEXT,
                severity TEXT,
                data TEXT
            )"""
        )
        self.conn.commit()
        logger.info(f"Alert store ready: {self.path}")

    def add(self, alert):
        with self.lock:
            self.conn.execute(
                "INSERT INTO alerts (timestamp, type, source_ip, source_port, service, severity, data) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    alert.get("timestamp"),
                    alert.get("type"),
                    alert.get("source_ip"),
                    alert.get("source_port"),
                    alert.get("service"),
                    alert.get("severity"),
                    alert.get("data"),
                ),
            )
            self.conn.commit()

    def load(self, limit=500):
        with self.lock:
            rows = self.conn.execute(
                "SELECT timestamp, type, source_ip, source_port, service, severity, data FROM alerts ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        alerts = []
        for r in reversed(rows):
            alert = {
                "timestamp": r[0],
                "type": r[1],
                "source_ip": r[2],
                "service": r[4],
                "severity": r[5],
            }
            if r[3] is not None:
                alert["source_port"] = r[3]
            if r[6]:
                alert["data"] = r[6]
            alerts.append(alert)
        return alerts

    def clear(self):
        with self.lock:
            self.conn.execute("DELETE FROM alerts")
            self.conn.commit()

alert_store = AlertStore()

class SystemMonitor:
    def __init__(self):
        self.primary_up = True
        self.backup_up = False
        self.active_connection = "primary"
        self.uptime_log = []
        self.honeypot_alerts = alert_store.load()

    def log_event(self, event_type, details):
        timestamp = datetime.now().isoformat()
        event = {"timestamp": timestamp, "type": event_type, "details": details}
        self.uptime_log.append(event)
        logger.info(f"{event_type}: {details}")

    def add_honeypot_alert(self, alert):
        alert["timestamp"] = datetime.now().isoformat()
        alert_store.add(alert)
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


# ============ NETWORK SCANNER ============

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 80: "http", 443: "https",
    139: "netbios", 445: "smb", 515: "printer", 554: "rtsp", 631: "ipp",
    8000: "http-alt", 8080: "http-alt", 8883: "mqtt", 9100: "raw-printer",
    3306: "mysql", 3389: "rdp", 49152: "upnp",
}

class NetworkScanner:
    """Sweeps the local /24 subnet for connected devices (ping + ARP + reverse
    DNS) and profiles each one: MAC vendor, open services, device type."""

    def __init__(self):
        self.devices = {}
        self.scanning = False
        self.progress = 0
        self.last_scan = None
        self.subnet = None
        self.local_ip = None
        self.vendor_cache = {}

    def is_locally_administered(self, mac):
        """Locally-administered MACs (Docker/random) have no registered vendor."""
        if not mac:
            return True
        try:
            return bool(int(mac.replace(":", "")[1], 16) & 0x2)
        except (ValueError, IndexError):
            return True

    def lookup_vendor(self, mac):
        """Resolve the device manufacturer from the IEEE MAC registry."""
        if not mac or self.is_locally_administered(mac) or mac in self.vendor_cache:
            return self.vendor_cache.get(mac, "")
        try:
            with urllib.request.urlopen(
                f"https://api.macvendors.com/{mac}", timeout=3
            ) as resp:
                vendor = resp.read().decode().strip()[:60]
            if vendor and "error" not in vendor.lower():
                self.vendor_cache[mac] = vendor
                return vendor
        except Exception:
            pass
        return ""

    def fingerprint_ports(self, ip):
        """Probe common service ports to fingerprint the device."""
        def check(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    return s.connect_ex((ip, port)) == 0
            except Exception:
                return False
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
            futures = {executor.submit(check, p): p for p in COMMON_PORTS}
            for future in concurrent.futures.as_completed(futures):
                if future.result():
                    open_ports.append(futures[future])
        return sorted(open_ports)

    def infer_device_type(self, open_ports, vendor):
        """Guess the device class from its services and manufacturer."""
        ps = set(open_ports or [])
        if ps & {9100, 631, 515}:
            return "Printer"
        if ps & {554}:
            return "Camera"
        if ps & {445, 139}:
            return "Windows Computer"
        if ps & {3389}:
            return "Windows Host"
        if ps & {5000, 8883, 49152}:
            return "IoT Device"
        if ps & {22}:
            return "Linux Host"
        v = (vendor or "").lower()
        if "apple" in v:
            return "Apple Device"
        if "samsung" in v:
            return "Samsung Device"
        if "xiaomi" in v:
            return "Xiaomi Device"
        if "raspberry" in v:
            return "Raspberry Pi"
        if ps & {80, 443, 8000, 8080}:
            return "Web Device"
        return "Unknown Device"

    def detect_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return None

    def get_mac(self, ip):
        try:
            with open('/proc/net/arp') as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if parts and parts[0] == ip:
                        return parts[3]
        except:
            pass
        return None

    def get_hostname(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return ""

    def ping(self, ip):
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                timeout=2, capture_output=True,
            )
            return result.returncode == 0
        except:
            return False

    def scan(self):
        if self.scanning:
            return
        self.scanning = True
        self.progress = 0
        try:
            local_ip = self.detect_local_ip()
            if not local_ip:
                return
            self.local_ip = local_ip
            prefix = local_ip.rsplit('.', 1)[0]
            self.subnet = f"{prefix}.0/24"
            ips = [f"{prefix}.{i}" for i in range(1, 255)]
            responded = set()
            with concurrent.futures.ThreadPoolExecutor(max_workers=64) as executor:
                futures = {executor.submit(self.ping, ip): ip for ip in ips}
                done = 0
                for future in concurrent.futures.as_completed(futures):
                    done += 1
                    self.progress = int((done / len(futures)) * 100)
                    ip = futures[future]
                    if future.result():
                        responded.add(ip)
                        now = datetime.now().isoformat()
                        if ip in self.devices:
                            device = self.devices[ip]
                            device["status"] = "online"
                            device["last_seen"] = now
                            device["open_ports"] = self.fingerprint_ports(ip)
                            device["device_type"] = self.infer_device_type(
                                device["open_ports"], device.get("vendor", "")
                            )
                        else:
                            mac = self.get_mac(ip)
                            vendor = self.lookup_vendor(mac)
                            open_ports = self.fingerprint_ports(ip)
                            self.devices[ip] = {
                                "ip": ip,
                                "hostname": self.get_hostname(ip),
                                "mac": mac,
                                "vendor": vendor,
                                "open_ports": open_ports,
                                "device_type": self.infer_device_type(open_ports, vendor),
                                "status": "online",
                                "first_seen": now,
                                "last_seen": now,
                            }
            for ip, device in self.devices.items():
                if ip not in responded:
                    device["status"] = "offline"
            self.last_scan = datetime.now().isoformat()
            logger.info(f"Network scan complete: {len(responded)} hosts up on {self.subnet}")
        except Exception as e:
            logger.error(f"Network scan error: {e}")
        finally:
            self.scanning = False
            self.progress = 100

    def start_scan_async(self):
        if self.scanning:
            return
        threading.Thread(target=self.scan, daemon=True).start()

    def to_dict(self):
        devices = sorted(
            self.devices.values(),
            key=lambda d: tuple(int(x) for x in d["ip"].split(".")),
        )
        return {
            "scanning": self.scanning,
            "progress": self.progress,
            "last_scan": self.last_scan,
            "subnet": self.subnet,
            "local_ip": self.local_ip,
            "devices": devices,
        }

network_scanner = NetworkScanner()
network_scanner.start_scan_async()


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


# ============ AUTHENTICATION ============

AUTH_USERNAME = "comradeonboard"
AUTH_PASSWORD_HASH = "783f8dd433cd2ea99d71123774474ef97067199ce9d67c36d31c953eeca5354a"
sessions = set()

def verify_password(password):
    return hashlib.sha256(password.encode()).hexdigest() == AUTH_PASSWORD_HASH

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if not path.startswith("/api/") or path == "/api/auth/login":
        return await call_next(request)
    auth = request.headers.get("Authorization", "")
    token = auth[7:] if auth.startswith("Bearer ") else ""
    if token in sessions:
        return await call_next(request)
    return JSONResponse({"detail": "Not authenticated"}, status_code=401)

@app.post("/api/auth/login")
async def login(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if body.get("username") == AUTH_USERNAME and verify_password(str(body.get("password", ""))):
        token = secrets.token_urlsafe(32)
        sessions.add(token)
        logger.info(f"Console login successful for '{AUTH_USERNAME}'")
        return {"ok": True, "token": token, "username": AUTH_USERNAME}
    logger.warning(f"Failed console login attempt for '{str(body.get('username', ''))[:50]}'")
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/api/auth/logout")
async def logout(request: Request):
    auth = request.headers.get("Authorization", "")
    token = auth[7:] if auth.startswith("Bearer ") else ""
    sessions.discard(token)
    return {"ok": True}

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
    alert_store.clear()
    logger.info("Honeypot alerts cleared")
    return {"ok": True, "cleared": True}

@app.get("/api/honeypot/stats")
def get_honeypot_stats():
    return compute_attack_stats()

@app.get("/api/network/devices")
def get_network_devices():
    return network_scanner.to_dict()

@app.post("/api/network/scan")
def trigger_network_scan():
    network_scanner.start_scan_async()
    return {"ok": True, "scanning": True}

@app.get("/health")
def health():
    return {"ok": True}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    token = websocket.query_params.get("token", "")
    if token not in sessions:
        await websocket.close(code=4401)
        return
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
                "network": network_scanner.to_dict(),
            }
            await websocket.send_json(data)
            await asyncio.sleep(2)
    except Exception:
        pass

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
