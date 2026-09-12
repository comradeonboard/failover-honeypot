import subprocess
import time
import threading
import socket
import concurrent.futures
import sqlite3
import os
import hashlib
import secrets
import urllib.request
import urllib.error
import re
import json
from urllib.parse import urlparse
from datetime import datetime
from fastapi import FastAPI, WebSocket, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse, FileResponse
from fastapi.staticfiles import StaticFiles
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

class HostStore:
    """Persists console hosts. The FIRST device ever to log in is the MAIN
    SERVER — permanently; every later device (e.g. a phone) is a SECOND HOST."""

    def __init__(self, path=DB_PATH):
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
        except OSError:
            path = "honeypot.db"
        self.path = path
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS hosts (
                device_id TEXT PRIMARY KEY,
                device TEXT, os TEXT, browser TEXT, ip TEXT,
                role TEXT, first_login TEXT, last_seen TEXT
            )"""
        )
        self.conn.commit()
        logger.info(f"Host store ready: {self.path}")

    def register(self, device_id, device, os_name, browser, ip):
        """Register or refresh a host. Returns its role ('main' or 'secondary')."""
        now = datetime.now().isoformat()
        with self.lock:
            row = self.conn.execute(
                "SELECT role FROM hosts WHERE device_id = ?", (device_id,)
            ).fetchone()
            if row:
                self.conn.execute(
                    "UPDATE hosts SET device=?, os=?, browser=?, ip=?, last_seen=? WHERE device_id=?",
                    (device, os_name, browser, ip, now, device_id),
                )
                self.conn.commit()
                return row[0]
            count = self.conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
            role = "main" if count == 0 else "secondary"
            self.conn.execute(
                "INSERT INTO hosts (device_id, device, os, browser, ip, role, first_login, last_seen) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (device_id, device, os_name, browser, ip, role, now, now),
            )
            self.conn.commit()
            return role

    def touch(self, device_id):
        """Mark a host as active (called throttled from the auth middleware)."""
        with self.lock:
            self.conn.execute(
                "UPDATE hosts SET last_seen=? WHERE device_id=?",
                (datetime.now().isoformat(), device_id),
            )
            self.conn.commit()

    def to_list(self):
        with self.lock:
            rows = self.conn.execute(
                "SELECT device_id, device, os, browser, ip, role, first_login, last_seen "
                "FROM hosts ORDER BY first_login ASC"
            ).fetchall()
        now = datetime.now()
        hosts = []
        for r in rows:
            try:
                active = (now - datetime.fromisoformat(r[7])).total_seconds() < 90
            except (TypeError, ValueError):
                active = False
            hosts.append({
                "device_id": r[0], "device": r[1], "os": r[2], "browser": r[3],
                "ip": r[4], "role": r[5], "first_login": r[6], "last_seen": r[7],
                "online": active,
            })
        return hosts

host_store = HostStore()


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
        defense.assess_alert(alert)

monitor = SystemMonitor()
monitor.log_event("MONITOR_START", "Monitoring service started")

# ============ DEFENSE SHIELD ============

DEFENSE_CONFIG = {
    "auto_ban_strikes": 3,     # honeypot strikes within window -> blacklist
    "strike_window": 300,      # seconds
    "ban_duration": 3600,      # first offence: 1 hour
    "flood_threshold": 15,    # honeypot connections per minute -> blacklist
}

class DefenseShield:
    """Heavy defensive layer: strike tracking, auto-ban engine, flood control,
    escalating permanent bans, and a persistent IP blocklist. Banned IPs are
    silently dropped by every honeypot handler."""

    def __init__(self):
        self.lock = threading.Lock()
        self.banned = {}
        self.strikes = {}
        self.flood = {}
        self.blocked_attempts = {}
        self.events = []
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS blocked_ips (
                ip TEXT PRIMARY KEY,
                reason TEXT,
                strikes INTEGER,
                banned_at TEXT,
                expires_at REAL
            )"""
        )
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS ban_history (
                ip TEXT PRIMARY KEY,
                count INTEGER DEFAULT 0
            )"""
        )
        self.conn.commit()
        rows = self.conn.execute(
            "SELECT ip, reason, strikes, banned_at, expires_at FROM blocked_ips"
        ).fetchall()
        for ip, reason, strikes, banned_at, expires_at in rows:
            self.banned[ip] = {
                "ip": ip, "reason": reason, "strikes": strikes,
                "banned_at": banned_at, "expires_at": expires_at,
                "permanent": expires_at is None,
            }
        if self.banned:
            logger.info(f"Defense shield: loaded {len(self.banned)} banned IP(s) from blocklist")

    def _event(self, etype, message):
        self.events.append({"timestamp": datetime.now().isoformat(), "type": etype, "message": message})
        if len(self.events) > 200:
            self.events = self.events[-200:]

    def is_banned(self, ip):
        with self.lock:
            info = self.banned.get(ip)
            if not info:
                return False
            exp = info.get("expires_at")
            if exp is not None and exp <= time.time():
                del self.banned[ip]
                self.conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
                self.conn.commit()
                self._event("BAN_EXPIRED", f"{ip} ban expired")
                return False
            return True

    def ban(self, ip, reason, strikes=0):
        now = time.time()
        with self.lock:
            self.conn.execute(
                "INSERT INTO ban_history (ip, count) VALUES (?, 1) "
                "ON CONFLICT(ip) DO UPDATE SET count = count + 1",
                (ip,),
            )
            row = self.conn.execute("SELECT count FROM ban_history WHERE ip = ?", (ip,)).fetchone()
            repeat = row[0] if row else 1
            permanent = repeat >= 2
            expires = None if permanent else now + DEFENSE_CONFIG["ban_duration"]
            info = {
                "ip": ip, "reason": reason, "strikes": strikes,
                "banned_at": datetime.now().isoformat(), "expires_at": expires,
                "permanent": permanent,
            }
            self.banned[ip] = info
            self.conn.execute(
                "INSERT OR REPLACE INTO blocked_ips (ip, reason, strikes, banned_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                (ip, reason, strikes, info["banned_at"], expires),
            )
            self.conn.commit()
        self._event("BAN", f"{ip} blacklisted — {reason} ({'permanent' if permanent else '1 hour'})")
        logger.warning(f"DEFENSE: {ip} blacklisted — {reason}")

    def unban(self, ip):
        with self.lock:
            removed = ip in self.banned
            if removed:
                del self.banned[ip]
                self.conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
                self.conn.commit()
        if removed:
            self._event("UNBAN", f"{ip} removed from blocklist")
        return removed

    def record_block(self, ip):
        with self.lock:
            self.blocked_attempts[ip] = self.blocked_attempts.get(ip, 0) + 1

    def record_strike(self, ip):
        now = time.time()
        with self.lock:
            strikes = self.strikes.setdefault(ip, [])
            strikes.append(now)
            self.strikes[ip] = [t for t in strikes if t > now - DEFENSE_CONFIG["strike_window"]]
            count = len(self.strikes[ip])
        if count >= DEFENSE_CONFIG["auto_ban_strikes"]:
            with self.lock:
                self.strikes.pop(ip, None)
            self.ban(ip, f"{count} honeypot strikes in {DEFENSE_CONFIG['strike_window'] // 60} min", count)

    def record_connection(self, ip):
        now = time.time()
        with self.lock:
            times = self.flood.setdefault(ip, [])
            times.append(now)
            self.flood[ip] = [t for t in times if t > now - 60]
            count = len(self.flood[ip])
        if count >= DEFENSE_CONFIG["flood_threshold"]:
            with self.lock:
                self.flood.pop(ip, None)
            self.ban(ip, f"connection flood ({count}/min)", count)

    def assess_alert(self, alert):
        ip = alert.get("source_ip")
        if not ip or ip.startswith("127.") or ip.startswith("::1"):
            return
        self.record_connection(ip)
        self.record_strike(ip)

    def to_dict(self):
        with self.lock:
            banned = [
                {**info, "blocked_attempts": self.blocked_attempts.get(ip, 0)}
                for ip, info in self.banned.items()
            ]
            events = list(self.events[-50:])
            total_blocked = sum(self.blocked_attempts.values())
        banned.sort(key=lambda b: b["banned_at"], reverse=True)
        return {
            "modules": [
                {"name": "Auto-Ban Engine", "detail": f"{DEFENSE_CONFIG['auto_ban_strikes']} strikes / {DEFENSE_CONFIG['strike_window'] // 60} min → blacklist"},
                {"name": "Flood Control", "detail": f"{DEFENSE_CONFIG['flood_threshold']} honeypot conns/min → blacklist"},
                {"name": "IP Blacklist", "detail": f"{len(banned)} IP(s) blocked, persistent"},
                {"name": "Escalation", "detail": "2nd offence = permanent ban"},
                {"name": "Login Lockout", "detail": "3 failed logins / 10 min"},
                {"name": "Decoy Shields", "detail": "4 honeypot ports dropping banned IPs"},
            ],
            "banned": banned,
            "events": events,
            "total_blocked_attempts": total_blocked,
        }

defense = DefenseShield()

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
    if defense.is_banned(address[0]):
        defense.record_block(address[0])
        try:
            client.close()
        except:
            pass
        return
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
    if defense.is_banned(address[0]):
        defense.record_block(address[0])
        try:
            client.close()
        except:
            pass
        return
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
    if defense.is_banned(address[0]):
        defense.record_block(address[0])
        try:
            client.close()
        except:
            pass
        return
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
    if defense.is_banned(address[0]):
        defense.record_block(address[0])
        try:
            client.close()
        except:
            pass
        return
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


# ============ WEB SECURITY SCANNER ============

SECURITY_HEADERS = {
    "strict-transport-security": ("Strict-Transport-Security (HSTS)", "medium",
        "Add a Strict-Transport-Security header to force HTTPS."),
    "content-security-policy": ("Content-Security-Policy", "high",
        "Add a CSP header to mitigate XSS and injection attacks."),
    "x-frame-options": ("X-Frame-Options", "medium",
        "Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking."),
    "x-content-type-options": ("X-Content-Type-Options", "low",
        "Set 'X-Content-Type-Options: nosniff' to stop MIME confusion."),
    "referrer-policy": ("Referrer-Policy", "low",
        "Set a Referrer-Policy to limit referrer leakage."),
    "permissions-policy": ("Permissions-Policy", "low",
        "Restrict powerful browser APIs (camera, geolocation, microphone)."),
}

SENSITIVE_PATHS = [
    (".git/HEAD", "high", "Exposed .git repository",
        "Restrict repository metadata — it leaks source code history."),
    (".env", "high", "Exposed environment file",
        "Block dotfiles — .env often holds credentials and keys."),
    (".env.local", "high", "Exposed environment file",
        "Block dotfiles — .env.local often holds credentials and keys."),
    ("backup.sql", "high", "Exposed database backup",
        "Remove database dumps from the web root."),
    ("dump.sql", "high", "Exposed database backup",
        "Remove database dumps from the web root."),
    (".svn/entries", "high", "Exposed .svn repository",
        "Restrict repository metadata from the web root."),
    ("phpinfo.php", "high", "Exposed phpinfo page",
        "Remove phpinfo pages from production — they leak server details."),
    ("admin", "medium", "Admin panel exposed",
        "Ensure admin surfaces are gated and not linked publicly."),
    ("server-status", "medium", "Apache server-status exposed",
        "Disable mod_status on production servers."),
    (".htaccess", "medium", "Exposed .htaccess file",
        "Block web-server config files from public access."),
    (".DS_Store", "low", "Exposed .DS_Store file",
        "Remove macOS metadata files — they leak directory listings."),
]

SEVERITY_PENALTY = {"high": 15, "medium": 8, "low": 4, "info": 0}

class WebSecurityScanner:
    """Audits a website for weak points: security headers, TLS, cookie flags,
    exposed sensitive files, banner disclosure, mixed content, robots recon."""

    def __init__(self):
        self.scans = {}
        self.lock = threading.Lock()
        try:
            self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        except Exception:
            self.conn = sqlite3.connect("honeypot.db", check_same_thread=False)
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                status TEXT,
                grade TEXT,
                score INTEGER,
                findings_count INTEGER,
                scanned_at TEXT,
                findings TEXT
            )"""
        )
        self.conn.commit()

    def _record(self, entry):
        """Persist a finished audit to the scan_history table."""
        try:
            findings = entry.get("findings", [])
            self.conn.execute(
                "INSERT INTO scan_history (target, status, grade, score, findings_count, scanned_at, findings) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    entry.get("target"),
                    entry.get("status"),
                    entry.get("grade"),
                    entry.get("score"),
                    len(findings),
                    entry.get("scanned_at"),
                    json.dumps(findings),
                ),
            )
            self.conn.commit()
        except Exception as err:
            logger.error(f"Failed to persist scan history: {err}")

    def normalize(self, target):
        target = (target or "").strip()[:200]
        if not target:
            return None
        parsed = urlparse(target)
        if not parsed.scheme:
            target = "https://" + target
            parsed = urlparse(target)
        if not parsed.netloc or " " in target:
            return None
        return f"{parsed.scheme}://{parsed.netloc}"

    def fetch(self, url, timeout=10):
        req = urllib.request.Request(url, headers={"User-Agent": "FHM-SecurityAudit/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                cookies = resp.headers.get_all("Set-Cookie") or []
                body = resp.read(400000).decode("utf-8", errors="ignore")
                return resp.status, headers, cookies, body
        except urllib.error.HTTPError as e:
            headers = {k.lower(): v for k, v in e.headers.items()}
            cookies = e.headers.get_all("Set-Cookie") or []
            return e.code, headers, cookies, ""
        except Exception:
            return None, {}, [], ""

    def scan(self, target):
        findings = []

        def add(severity, title, detail, fix):
            findings.append({"severity": severity, "title": title, "detail": detail, "fix": fix})

        status, headers, cookies, body = self.fetch(target)
        if status is None:
            entry = {
                "target": target,
                "status": "error",
                "findings": [],
                "scanned_at": datetime.now().isoformat(),
            }
            with self.lock:
                self.scans[target] = entry
            self._record(entry)
            return

        if not target.startswith("https://"):
            add("high", "No HTTPS",
                "Target is served over plain HTTP — all traffic is readable in transit.",
                "Serve content over TLS and redirect HTTP to HTTPS.")

        for header, (title, severity, fix) in SECURITY_HEADERS.items():
            if header not in headers:
                add(severity, f"Missing {title}",
                    f"The response does not include the {title} header.", fix)

        server = headers.get("server")
        if server:
            add("low", "Server banner disclosed",
                f"The Server header reveals the technology: {server[:80]}",
                "Suppress or genericize the Server header.")
        powered = headers.get("x-powered-by")
        if powered:
            add("low", "Technology stack disclosed",
                f"X-Powered-By reveals: {powered[:80]}",
                "Remove the X-Powered-By header.")

        for cookie in cookies:
            name = cookie.split("=")[0].strip()[:50]
            low = cookie.lower()
            if "secure" not in low:
                add("medium", "Cookie without Secure flag",
                    f"Cookie '{name}' may be sent over plain HTTP.",
                    "Set the Secure flag on all cookies.")
            if "httponly" not in low:
                add("medium", "Cookie without HttpOnly",
                    f"Cookie '{name}' is readable by JavaScript (XSS theft risk).",
                    "Set the HttpOnly flag on session cookies.")
            if "samesite" not in low:
                add("low", "Cookie without SameSite",
                    f"Cookie '{name}' lacks cross-site request protection.",
                    "Set SameSite=Lax or Strict.")

        if target.startswith("https://") and body:
            mixed = re.findall(r'(?:src|href)="http://[^"]*"', body)
            if mixed:
                add("medium", "Mixed content",
                    f"{len(mixed)} insecure http:// resource(s) loaded on the HTTPS page.",
                    "Load all subresources over HTTPS.")

        origin = f"{urlparse(target).scheme}://{urlparse(target).netloc}"
        root_sig = (body or "").strip()[:300]
        for path, severity, title, fix in SENSITIVE_PATHS:
            p_status, _, _, p_body = self.fetch(f"{origin}/{path}", timeout=8)
            if p_status == 200:
                if path == ".git/HEAD" and "ref:" not in p_body[:200]:
                    continue
                # SPA fallback servers answer any path with the index page
                if root_sig and p_body.strip()[:300] == root_sig:
                    continue
                add(severity, title, f"/{path} is publicly accessible (HTTP 200).", fix)

        r_status, _, _, r_body = self.fetch(f"{origin}/robots.txt", timeout=8)
        if r_status == 200 and r_body.strip() and not (
            root_sig and r_body.strip()[:300] == root_sig
        ):
            disallows = [
                line.split(":", 1)[1].strip()
                for line in r_body.splitlines()
                if line.lower().startswith("disallow:")
            ]
            if disallows:
                preview = ", ".join(disallows[:5])
                add("info", "robots.txt recon",
                    f"robots.txt discloses {len(disallows)} hidden path(s): {preview[:200]}",
                    "Do not rely on robots.txt for protection; review whether listed paths should be secret.")

        score = max(0, 100 - sum(SEVERITY_PENALTY.get(f["severity"], 0) for f in findings))
        grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
        entry = {
            "target": target,
            "status": "complete",
            "score": score,
            "grade": grade,
            "findings": findings,
            "scanned_at": datetime.now().isoformat(),
        }
        with self.lock:
            self.scans[target] = entry
        self._record(entry)
        logger.info(f"Web security audit of {target}: grade {grade} ({score}/100), {len(findings)} findings")

    def start_scan(self, target):
        with self.lock:
            if self.scans.get(target, {}).get("status") == "scanning":
                return
            self.scans[target] = {
                "target": target,
                "status": "scanning",
                "findings": [],
                "scanned_at": datetime.now().isoformat(),
            }
        threading.Thread(target=self.scan, args=(target,), daemon=True).start()

    def to_dict(self):
        with self.lock:
            scans = sorted(self.scans.values(), key=lambda s: s["scanned_at"], reverse=True)
        return {"scans": scans[:20]}

    def history(self, limit=100):
        """Past audits, most recent first, persisted across restarts."""
        rows = self.conn.execute(
            "SELECT id, target, status, grade, score, findings_count, scanned_at, findings "
            "FROM scan_history ORDER BY scanned_at DESC, id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return {
            "history": [
                {
                    "id": r[0],
                    "target": r[1],
                    "status": r[2],
                    "grade": r[3],
                    "score": r[4],
                    "findings_count": r[5],
                    "scanned_at": r[6],
                    "findings": json.loads(r[7]) if r[7] else [],
                }
                for r in rows
            ]
        }

web_scanner = WebSecurityScanner()

# ============ AUTHENTICATION ============

AUTH_USERNAME = "comradeonboard"
AUTH_PASSWORD_HASH = "783f8dd433cd2ea99d71123774474ef97067199ce9d67c36d31c953eeca5354a"
MAX_LOGIN_FAILURES = 3
LOGIN_LOCKOUT_SECONDS = 600
sessions = {}  # token -> device_id
host_last_touch = {}  # device_id -> epoch of last activity update (throttle)
login_attempts = {}

def parse_device(ua):
    """Classify the device, OS and browser from a User-Agent string."""
    ua_l = (ua or "").lower()
    if "ipad" in ua_l or ("android" in ua_l and "mobile" not in ua_l):
        device = "Tablet"
    elif "iphone" in ua_l or ("android" in ua_l and "mobile" in ua_l) or "mobile" in ua_l:
        device = "Phone"
    else:
        device = "Desktop / Laptop"
    if "android" in ua_l:
        os_name = "Android"
    elif "linux" in ua_l:
        os_name = "Linux"
    elif "windows" in ua_l:
        os_name = "Windows"
    elif "iphone" in ua_l or "ipad" in ua_l:
        os_name = "iOS"
    elif "macintosh" in ua_l or "mac os" in ua_l:
        os_name = "macOS"
    else:
        os_name = "Unknown OS"
    if "edg/" in ua_l:
        browser = "Edge"
    elif "opr/" in ua_l or "opera" in ua_l:
        browser = "Opera"
    elif "chrome" in ua_l:
        browser = "Chrome"
    elif "firefox" in ua_l:
        browser = "Firefox"
    elif "safari" in ua_l:
        browser = "Safari"
    else:
        browser = "Unknown Browser"
    return device, os_name, browser

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
        device_id = sessions[token]
        now = time.time()
        if now - host_last_touch.get(device_id, 0) > 30:
            host_last_touch[device_id] = now
            host_store.touch(device_id)
        return await call_next(request)
    return JSONResponse({"detail": "Not authenticated"}, status_code=401)

@app.post("/api/auth/login")
async def login(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    attempt = login_attempts.get(client_ip, {"failures": 0, "locked_until": 0.0})
    if attempt["locked_until"] > now:
        retry_after = int(attempt["locked_until"] - now)
        logger.warning(f"Login blocked for '{client_ip}' — locked, {retry_after}s remaining")
        raise HTTPException(
            status_code=429,
            detail={"locked": True, "retry_after": retry_after},
        )
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if body.get("username") == AUTH_USERNAME and verify_password(str(body.get("password", ""))):
        token = secrets.token_urlsafe(32)
        device_id = str(body.get("device_id", ""))[:100] or f"anon-{secrets.token_hex(8)}"
        device, os_name, browser = parse_device(request.headers.get("User-Agent", ""))
        role = host_store.register(device_id, device, os_name, browser, client_ip)
        sessions[token] = device_id
        login_attempts[client_ip] = {"failures": 0, "locked_until": 0.0}
        logger.info(
            f"Console login from {os_name} {device} ({client_ip}) as '{AUTH_USERNAME}' — role: {role}"
        )
        return {"ok": True, "token": token, "username": AUTH_USERNAME, "role": role}
    attempt["failures"] += 1
    if attempt["failures"] >= MAX_LOGIN_FAILURES:
        attempt["failures"] = 0
        attempt["locked_until"] = now + LOGIN_LOCKOUT_SECONDS
        login_attempts[client_ip] = attempt
        logger.warning(f"Login locked for '{client_ip}' after {MAX_LOGIN_FAILURES} failed attempts")
        raise HTTPException(
            status_code=429,
            detail={"locked": True, "retry_after": LOGIN_LOCKOUT_SECONDS},
        )
    login_attempts[client_ip] = attempt
    logger.warning(f"Failed console login attempt for '{str(body.get('username', ''))[:50]}'")
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/api/auth/logout")
async def logout(request: Request):
    auth = request.headers.get("Authorization", "")
    token = auth[7:] if auth.startswith("Bearer ") else ""
    sessions.pop(token, None)
    return {"ok": True}

@app.get("/api/auth/hosts")
def get_hosts():
    return {"hosts": host_store.to_list()}

# ============ API ROUTES ============

@app.get("/api/ping")
def ping():
    return {"status": "ok", "message": "Failover Monitor Running"}

# ============ FRONTEND (built React UI) ============
# The catch-all SPA route is registered at the END of the file
# (see serve_spa below) so every real API route takes precedence.

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

@app.get("/api/security/scans")
def get_security_scans():
    return web_scanner.to_dict()

@app.get("/api/security/history")
def get_security_history():
    return web_scanner.history()

@app.post("/api/security/scan")
async def scan_site(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    normalized = web_scanner.normalize(str(body.get("target", "")))
    if not normalized:
        raise HTTPException(status_code=400, detail="Invalid target")
    web_scanner.start_scan(normalized)
    return {"ok": True, "target": normalized}



@app.get("/api/defense/status")
def get_defense_status():
    return defense.to_dict()

@app.post("/api/defense/ban")
async def manual_ban(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    ip = str(body.get("ip", "")).strip()[:64]
    if not ip or " " in ip:
        raise HTTPException(status_code=400, detail="Invalid IP")
    defense.ban(ip, str(body.get("reason", "manual block"))[:100])
    return {"ok": True}

@app.post("/api/defense/unban")
async def manual_unban(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    ip = str(body.get("ip", "")).strip()[:64]
    return {"ok": defense.unban(ip)}

@app.get("/api/defense/export")
def export_blocklist():
    lines = ["# FHM persistent blocklist — apply with: iptables -A INPUT -s <ip> -j DROP"]
    with defense.lock:
        lines.extend(sorted(defense.banned.keys()))
    return PlainTextResponse("\n".join(lines) + "\n")

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
                "defense": defense.to_dict(),
            }
            await websocket.send_json(data)
            await asyncio.sleep(2)
    except Exception:
        pass

# ============ FRONTEND (built React UI) ============
# Registered last so all API routes above take precedence.
from pathlib import Path

DIST_DIR = Path(__file__).parent / "frontend" / "dist"

if (DIST_DIR / "index.html").exists():
    app.mount("/assets", StaticFiles(directory=DIST_DIR / "assets"), name="assets")

    @app.get("/", include_in_schema=False)
    def serve_ui():
        return FileResponse(DIST_DIR / "index.html")

    @app.get("/{full_path:path}", include_in_schema=False)
    def serve_spa(full_path: str):
        candidate = DIST_DIR / full_path
        if full_path and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(DIST_DIR / "index.html")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
