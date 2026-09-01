#!/usr/bin/env python3
"""
GARUDA Agent - run this on a friend's laptop to join the live enterprise/attacker
exercise. Reports REAL local network connections, the owning process, and the
logged-in user to a GARUDA backend over your LAN, using psutil (no admin/root
privileges, no packet capture/sniffing - just what your own OS already knows
about your own machine).

    pip install -r requirements.txt

    # Join as a regular enterprise workstation (the default):
    python garuda_agent.py join --server http://<host-laptop-ip>:8123 --name "Alex-Laptop"

    # Simulate a (capped, rate-limited) DoS flood against a CONSENTING teammate,
    # for demonstrating GARUDA's DoS detection - not a real attack tool:
    python garuda_agent.py attack --server http://<host-laptop-ip>:8123 --target <their-ip>

Everything this script reports is visible only to the GARUDA server you point it
at. Only run it against a server you and your friends control, and only use
`attack` mode against a machine whose owner has agreed to take part.
"""
import argparse
import getpass
import json
import platform
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone

import psutil
import requests

POLL_SECONDS = 3
MAX_CONNECTIONS_PER_HEARTBEAT = 40
MAX_SEEN_KEYS = 4000
DNS_CACHE_REFRESH_SECONDS = 20

ATTACK_MAX_DURATION_S = 30
ATTACK_MAX_RATE_PER_S = 60

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def local_ip() -> str:
    """Asks the OS which local interface would be used to reach the internet.
    Sends no actual data (UDP connect() just picks a route)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def snapshot_processes(limit=10):
    procs = []
    for p in psutil.process_iter(["pid", "name", "username"]):
        try:
            info = p.info
            if info["name"]:
                procs.append({"pid": info["pid"], "name": info["name"], "username": info["username"]})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        if len(procs) >= limit:
            break
    return procs


def snapshot_connections(seen_keys):
    """Returns newly-observed real network connections since the last poll, each
    attributed to the owning process + user where the OS permits it."""
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        print("[garuda-agent] warning: OS denied access to the connection table "
              "(try running as admin/root for full visibility). Reporting processes only.")
        return []

    out = []
    for c in conns:
        if not c.raddr or not c.laddr:
            continue
        key = (c.laddr.ip, c.laddr.port, c.raddr.ip, c.raddr.port, c.status)
        if key in seen_keys:
            continue
        seen_keys.add(key)

        proc_name, username = None, None
        if c.pid:
            try:
                p = psutil.Process(c.pid)
                proc_name, username = p.name(), p.username()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        out.append({
            "event_type": "network_connection",
            "source_ip": c.laddr.ip, "source_port": c.laddr.port,
            "destination_ip": c.raddr.ip, "destination_port": c.raddr.port,
            "protocol": "TCP", "process": proc_name, "username": username,
            "conn_status": c.status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        if len(out) >= MAX_CONNECTIONS_PER_HEARTBEAT:
            break
    return out


def dns_cache_snapshot():
    """Best-effort {ip: hostname} map from this machine's own DNS resolver cache —
    what THIS laptop actually resolved when it made a connection, which is far more
    accurate for "what site is this" than a server-side reverse-DNS guess (many IPs,
    especially CDNs, have no useful PTR record at all). Windows only for now
    (Get-DnsClientCache); other platforms just get no name enrichment from here and
    fall back to the server's reverse-DNS/known-asset lookup."""
    if platform.system() != "Windows":
        return {}
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-DnsClientCache | Select-Object Entry,Data | ConvertTo-Json -Compress"],
            capture_output=True, text=True, timeout=4,
        )
        raw = result.stdout.strip()
        if not raw:
            return {}
        records = json.loads(raw)
        if isinstance(records, dict):
            records = [records]
        mapping = {}
        for r in records:
            ip, name = r.get("Data"), r.get("Entry")
            if ip and name and _IPV4_RE.match(ip):
                mapping[ip] = name
        return mapping
    except Exception:
        return {}


def post(server, path, payload):
    resp = requests.post(f"{server}{path}", json=payload, timeout=10)
    resp.raise_for_status()
    return resp.json()


def run_monitor(server, asset_id):
    seen_keys = set()
    dns_cache = {}
    next_dns_refresh = 0.0
    print(f"[garuda-agent] reporting live connections/processes every {POLL_SECONDS}s. Ctrl+C to stop.")
    while True:
        try:
            conns = snapshot_connections(seen_keys)
            if time.time() >= next_dns_refresh:
                dns_cache = dns_cache_snapshot()
                next_dns_refresh = time.time() + DNS_CACHE_REFRESH_SECONDS
            asset = post(server, f"/api/agents/{asset_id}/heartbeat", {
                "current_user": getpass.getuser(),
                "processes": snapshot_processes(),
                "connections": conns,
                "dns_cache": dns_cache,
            })
            if asset.get("role") == "attacker":
                print("[garuda-agent] NOTE: GARUDA has flagged this machine as ATTACKER "
                      "based on observed activity.")
        except requests.RequestException as exc:
            print(f"[garuda-agent] heartbeat failed: {exc}")
        if len(seen_keys) > MAX_SEEN_KEYS:
            seen_keys.clear()
        time.sleep(POLL_SECONDS)


def cmd_join(args):
    server = args.server.rstrip("/")
    hostname = socket.gethostname()
    ip = local_ip()
    asset = post(server, "/api/agents/register", {
        "name": args.name or hostname,
        "hostname": hostname,
        "ip_address": ip,
        "os_info": f"{platform.system()} {platform.release()}",
        "role": args.role,
        "current_user": getpass.getuser(),
        "criticality": args.criticality,
    })
    print(f"[garuda-agent] registered as '{asset['name']}' ({ip}) - role={asset['role']} - asset_id={asset['asset_id']}")
    run_monitor(server, asset["asset_id"])


def cmd_attack(args):
    """A deliberately capped, rate-limited TCP connect() flood for demonstrating
    GARUDA's DoS detection - NOT a real denial-of-service tool. Duration and rate
    are hard-capped so it cannot meaningfully impact a target. Only run this
    against a machine whose owner has agreed to take part in the exercise."""
    duration = min(args.duration, ATTACK_MAX_DURATION_S)
    rate = min(args.rate, ATTACK_MAX_RATE_PER_S)
    server = args.server.rstrip("/")

    hostname = socket.gethostname()
    ip = local_ip()
    asset = post(server, "/api/agents/register", {
        "name": args.name or hostname,
        "hostname": hostname,
        "ip_address": ip,
        "os_info": f"{platform.system()} {platform.release()}",
        "role": "attacker",
        "current_user": getpass.getuser(),
        "criticality": "medium",
    })
    asset_id = asset["asset_id"]

    print(f"[garuda-agent] SIMULATED DoS flood -> {args.target}:{args.port} for {duration}s at ~{rate}/s (capped).")
    print("[garuda-agent] Only run this against a machine whose owner has agreed to take part.")

    stop_at = time.time() + duration
    total = 0
    try:
        while time.time() < stop_at:
            batch_start = time.time()
            batch = []
            for i in range(rate):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.3)
                    s.connect_ex((args.target, args.port))
                    s.close()
                except OSError:
                    pass
                batch.append({
                    "event_type": "network_connection",
                    "source_ip": ip, "source_port": 40000 + ((total + i) % 20000),
                    "destination_ip": args.target, "destination_port": args.port,
                    "protocol": "TCP", "process": "garuda_agent (simulated flood)", "username": getpass.getuser(),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
            total += len(batch)
            try:
                post(server, f"/api/agents/{asset_id}/heartbeat", {"connections": batch})
            except requests.RequestException as exc:
                print(f"[garuda-agent] report failed: {exc}")
            elapsed = time.time() - batch_start
            time.sleep(max(0.0, 1.0 - elapsed))
    except KeyboardInterrupt:
        pass

    print(f"[garuda-agent] done - {total} connection attempts sent and reported.")


def main():
    parser = argparse.ArgumentParser(description="GARUDA Agent - join the live exercise or simulate a DoS flood.")
    sub = parser.add_subparsers(dest="command", required=True)

    join = sub.add_parser("join", help="Register this laptop and start reporting live telemetry")
    join.add_argument("--server", required=True, help="GARUDA backend URL, e.g. http://192.168.1.20:8123")
    join.add_argument("--name", default=None, help="Display name for this laptop")
    join.add_argument("--role", default="enterprise", choices=["enterprise", "attacker", "unknown"])
    join.add_argument("--criticality", default="medium", choices=["low", "medium", "high", "critical"])
    join.set_defaults(func=cmd_join)

    attack = sub.add_parser("attack", help="Simulated, capped DoS flood against a consenting target")
    attack.add_argument("--server", required=True)
    attack.add_argument("--target", required=True, help="Target IP - must belong to a consenting participant")
    attack.add_argument("--port", type=int, default=80)
    attack.add_argument("--duration", type=int, default=10, help=f"Seconds, hard-capped at {ATTACK_MAX_DURATION_S}")
    attack.add_argument("--rate", type=int, default=20, help=f"Connections/sec, hard-capped at {ATTACK_MAX_RATE_PER_S}")
    attack.add_argument("--name", default=None)
    attack.set_defaults(func=cmd_attack)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    except requests.RequestException as exc:
        print(f"[garuda-agent] could not reach the GARUDA server: {exc}")
        sys.exit(1)
