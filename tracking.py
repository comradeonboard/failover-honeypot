"""Persistent tracking stores for the FHM console:
- SslStore: TLS certificate expiry monitoring for registered hosts
- DeviceStore: known-device inventory with new-device alerts
- UptimeStore: status samples powering uptime-percentage reports
"""
import os
import ssl
import socket
import sqlite3
import threading
import time
import logging
import re
from datetime import datetime, timezone

logger = logging.getLogger("fhm.tracking")

DB_PATH = os.environ.get("HONEYPOT_DB", "/app/data/honeypot.db")


class SslStore:
    """Tracks TLS certificates and warns before they expire."""

    CHECK_INTERVAL = 6 * 3600  # re-check every 6 hours

    def __init__(self):
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS ssl_targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT UNIQUE NOT NULL,
                added_at TEXT NOT NULL,
                last_check TEXT,
                expires_at TEXT,
                days_left INTEGER,
                issuer TEXT,
                status TEXT DEFAULT 'pending'
            )"""
        )
        self.conn.commit()
        self._recheck_all()
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            time.sleep(self.CHECK_INTERVAL)
            self._recheck_all()

    def _recheck_all(self):
        for (host,) in self.conn.execute("SELECT host FROM ssl_targets").fetchall():
            self.check(host)

    def _probe(self, host):
        """Connect on 443 and read the peer certificate. Raises on failure."""
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
        not_after = " ".join(cert["notAfter"].split())
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        issuer_bits = {k: v for part in cert.get("issuer", ()) for k, v in part}
        issuer = issuer_bits.get("organizationName") or issuer_bits.get("commonName") or ""
        days = (expires - datetime.now(timezone.utc)).days
        return expires.strftime("%Y-%m-%d"), days, issuer

    @staticmethod
    def _status(days):
        if days is None:
            return "error"
        if days < 0:
            return "expired"
        if days < 7:
            return "critical"
        if days < 30:
            return "expiring"
        return "valid"

    def check(self, host):
        """Probe one host and store the result."""
        try:
            expires_at, days, issuer = self._probe(host)
            status = self._status(days)
            logger.info(f"SSL check {host}: {status}, {days} day(s) left")
        except Exception as e:
            expires_at, days, issuer, status = None, None, None, "error"
            logger.warning(f"SSL check failed for {host}: {e}")
        with self.lock:
            self.conn.execute(
                "UPDATE ssl_targets SET last_check=?, expires_at=?, days_left=?, issuer=?, status=? "
                "WHERE host=?",
                (datetime.now().isoformat(), expires_at, days, issuer, status, host),
            )
            self.conn.commit()

    def add(self, raw_host):
        host = raw_host.strip().lower()
        if host.startswith(("https://", "http://")):
            host = host.split("://", 1)[1].split("/", 1)[0]
        if not re.match(r"^[a-z0-9.-]+$", host):
            return {"error": "Enter a valid hostname (e.g. example.com)"}
        with self.lock:
            existing = self.conn.execute(
                "SELECT id FROM ssl_targets WHERE host=?", (host,)
            ).fetchone()
            if existing:
                return {"error": f"{host} is already tracked"}
            self.conn.execute(
                "INSERT INTO ssl_targets (host, added_at) VALUES (?, ?)",
                (host, datetime.now().isoformat()),
            )
            self.conn.commit()
        self.check(host)
        return {"ok": True}

    def remove(self, target_id):
        with self.lock:
            self.conn.execute("DELETE FROM ssl_targets WHERE id=?", (target_id,))
            self.conn.commit()
        return {"ok": True}

    def list(self):
        with self.lock:
            rows = self.conn.execute(
                "SELECT id, host, added_at, last_check, expires_at, days_left, issuer, status "
                "FROM ssl_targets ORDER BY host"
            ).fetchall()
        return {
            "targets": [
                {
                    "id": r[0], "host": r[1], "added_at": r[2], "last_check": r[3],
                    "expires_at": r[4], "days_left": r[5], "issuer": r[6], "status": r[7],
                }
                for r in rows
            ]
        }


class DeviceStore:
    """Remembers every device seen on the network and raises an alert
    the first time an unknown device appears."""

    def __init__(self):
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS known_devices (
                key TEXT PRIMARY KEY,
                ip TEXT, hostname TEXT, vendor TEXT, device_type TEXT,
                first_seen TEXT, last_seen TEXT
            )"""
        )
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS device_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT, mac TEXT, hostname TEXT, vendor TEXT,
                detected_at TEXT, acknowledged INTEGER DEFAULT 0
            )"""
        )
        self.conn.commit()

    def sync(self, devices):
        """Compare scan results against the inventory; flag anything new."""
        now = datetime.now().isoformat()
        new_count = 0
        with self.lock:
            for d in devices.values():
                key = d.get("mac") or f"ip:{d['ip']}"
                row = self.conn.execute(
                    "SELECT key FROM known_devices WHERE key=?", (key,)
                ).fetchone()
                if row:
                    self.conn.execute(
                        "UPDATE known_devices SET ip=?, hostname=?, vendor=?, last_seen=? WHERE key=?",
                        (d["ip"], d.get("hostname"), d.get("vendor"), now, key),
                    )
                else:
                    self.conn.execute(
                        "INSERT INTO known_devices (key, ip, hostname, vendor, device_type, first_seen, last_seen) "
                        "VALUES (?,?,?,?,?,?,?)",
                        (key, d["ip"], d.get("hostname"), d.get("vendor"),
                         d.get("device_type"), now, now),
                    )
                    self.conn.execute(
                        "INSERT INTO device_alerts (ip, mac, hostname, vendor, detected_at) "
                        "VALUES (?,?,?,?,?)",
                        (d["ip"], d.get("mac"), d.get("hostname"), d.get("vendor"), now),
                    )
                    new_count += 1
                    logger.warning(f"NEW DEVICE on network: {d['ip']} ({d.get('hostname') or 'unknown'})")
            self.conn.commit()
        return new_count

    def list(self):
        with self.lock:
            devices = self.conn.execute(
                "SELECT ip, hostname, vendor, device_type, first_seen, last_seen "
                "FROM known_devices ORDER BY first_seen DESC"
            ).fetchall()
            alerts = self.conn.execute(
                "SELECT id, ip, mac, hostname, vendor, detected_at FROM device_alerts "
                "WHERE acknowledged=0 ORDER BY detected_at DESC"
            ).fetchall()
            total = self.conn.execute("SELECT COUNT(*) FROM known_devices").fetchone()[0]
        order = lambda ip: tuple(int(x) if x.isdigit() else 255 for x in ip.split("."))
        return {
            "devices": [
                {
                    "ip": r[0], "hostname": r[1], "vendor": r[2], "device_type": r[3],
                    "first_seen": r[4], "last_seen": r[5],
                }
                for r in sorted(devices, key=lambda r: order(r[0]))
            ],
            "alerts": [
                {
                    "id": r[0], "ip": r[1], "mac": r[2], "hostname": r[3],
                    "vendor": r[4], "detected_at": r[5],
                }
                for r in alerts
            ],
            "total_known": total,
        }

    def ack(self, alert_id):
        with self.lock:
            self.conn.execute(
                "UPDATE device_alerts SET acknowledged=1 WHERE id=?", (alert_id,)
            )
            self.conn.commit()
        return {"ok": True}

    def ack_all(self):
        with self.lock:
            self.conn.execute("UPDATE device_alerts SET acknowledged=1 WHERE acknowledged=0")
            self.conn.commit()
        return {"ok": True}


class UptimeStore:
    """Samples system status once a minute so uptime can be reported as a %."""

    SAMPLE_INTERVAL = 60

    def __init__(self):
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS status_samples (
                ts INTEGER PRIMARY KEY,
                primary_up INTEGER,
                backup_up INTEGER
            )"""
        )
        self.conn.commit()
        row = self.conn.execute("SELECT MAX(ts) FROM status_samples").fetchone()
        self._last = row[0] if row and row[0] else None

    def record(self, primary_up, backup_up):
        now = int(time.time())
        if self._last and now - self._last < self.SAMPLE_INTERVAL:
            return
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO status_samples (ts, primary_up, backup_up) VALUES (?,?,?)",
                (now, int(primary_up), int(backup_up)),
            )
            self.conn.commit()
        self._last = now

    def report(self, days=30):
        cutoff = int(time.time()) - days * 86400
        with self.lock:
            summary = self.conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(primary_up),0), COALESCE(SUM(backup_up),0), MIN(ts) "
                "FROM status_samples WHERE ts>=?",
                (cutoff,),
            ).fetchone()
            daily = self.conn.execute(
                "SELECT date(ts,'unixepoch','localtime') d, COUNT(*), "
                "COALESCE(SUM(primary_up),0), COALESCE(SUM(backup_up),0) "
                "FROM status_samples WHERE ts>=? GROUP BY d ORDER BY d",
                (cutoff,),
            ).fetchall()
            # count up->down transitions (incidents) in one pass
            rows = self.conn.execute(
                "SELECT primary_up, backup_up FROM status_samples WHERE ts>=? ORDER BY ts",
                (cutoff,),
            ).fetchall()
        total, p_up, b_up, first_ts = summary
        p_inc = b_inc = 0
        prev_p = prev_b = 1
        for p, b in rows:
            if prev_p == 1 and p == 0:
                p_inc += 1
            if prev_b == 1 and b == 0:
                b_inc += 1
            prev_p, prev_b = p, b
        return {
            "days": days,
            "primary": {
                "uptime_pct": round(p_up / total * 100, 2) if total else None,
                "incidents": p_inc,
            },
            "backup": {
                "uptime_pct": round(b_up / total * 100, 2) if total else None,
                "incidents": b_inc,
            },
            "samples": total,
            "tracked_since": (
                datetime.fromtimestamp(first_ts).isoformat() if first_ts else None
            ),
            "daily": [
                {
                    "date": r[0],
                    "primary_pct": round(r[2] / r[1] * 100, 1) if r[1] else None,
                    "backup_pct": round(r[3] / r[1] * 100, 1) if r[1] else None,
                }
                for r in daily
            ],
        }


ssl_store = SslStore()
device_store = DeviceStore()
uptime_store = UptimeStore()
