"""
Predefined, reproducible attack scenarios for Sample Mode.

Each scenario is a list of (delay_seconds, event_dict) tuples. delay_seconds is
relative to scenario start; the player (see player.py) releases each event at
that offset (scaled by a speed multiplier), so Sample Mode exercises exactly the
same ingestion -> normalize -> detect -> correlate -> agents -> dashboard
pipeline as a live sensor would.
"""

ATTACKER_IP = "45.33.12.7"
VICTIM_IP = "192.168.56.10"
VICTIM_HOST = "web01.internal"


def _conn(delay, sport, dport, proto="TCP"):
    return delay, {
        "event_type": "network_connection",
        "source_ip": ATTACKER_IP,
        "destination_ip": VICTIM_IP,
        "source_port": sport,
        "destination_port": dport,
        "protocol": proto,
        "severity": "info",
        "message": f"Connection {ATTACKER_IP}:{sport} -> {VICTIM_IP}:{dport} ({proto})",
    }


def _auth_fail(delay, username="root"):
    return delay, {
        "event_type": "auth_failure",
        "source_ip": ATTACKER_IP,
        "destination_ip": VICTIM_IP,
        "hostname": VICTIM_HOST,
        "username": username,
        "process": "sshd",
        "severity": "low",
        "message": f"Failed password for {username} from {ATTACKER_IP} port 22 ssh2",
    }


def _auth_success(delay, username="root"):
    return delay, {
        "event_type": "auth_success",
        "source_ip": ATTACKER_IP,
        "destination_ip": VICTIM_IP,
        "hostname": VICTIM_HOST,
        "username": username,
        "process": "sshd",
        "severity": "info",
        "message": f"Accepted password for {username} from {ATTACKER_IP} port 22 ssh2",
    }


def _privesc(delay, username="root"):
    return delay, {
        "event_type": "privilege_escalation",
        "source_ip": ATTACKER_IP,
        "destination_ip": VICTIM_IP,
        "hostname": VICTIM_HOST,
        "username": username,
        "process": "sudo",
        "severity": "high",
        "message": f"User {username} executed 'sudo su -' on {VICTIM_HOST}",
    }


def _c2(delay):
    return delay, {
        "event_type": "suspicious_outbound",
        "source_ip": VICTIM_IP,
        "destination_ip": "185.220.101.4",
        "destination_port": 4444,
        "protocol": "TCP",
        "hostname": VICTIM_HOST,
        "severity": "high",
        "message": f"{VICTIM_HOST} initiated outbound connection to 185.220.101.4:4444 (uncommon port, no prior DNS lookup)",
    }


def _web_attack(delay):
    return delay, {
        "event_type": "ids_alert",
        "source": "suricata",
        "source_ip": ATTACKER_IP,
        "destination_ip": VICTIM_IP,
        "destination_port": 80,
        "protocol": "TCP",
        "severity": "high",
        "message": "ET WEB_SERVER SQL Injection Attempt in URI",
    }


def port_scan():
    ports = [21, 22, 23, 25, 80, 443, 3306, 3389, 8080]
    return [_conn(i * 0.6, 40000 + i, p) for i, p in enumerate(ports)]


def ssh_brute_force():
    events = [_auth_fail(2 * i, "root") for i in range(6)]
    events.append(_auth_success(13, "root"))
    return events


def credential_compromise():
    return ssh_brute_force()


def web_attack():
    return [_web_attack(0)]


def multi_stage_attack():
    events = []
    events += port_scan()                                        # t ~ 0-5s   recon
    events += [(_d + 8, e) for _d, e in ssh_brute_force()]        # t ~ 8-21s  brute force + login
    events.append(_privesc(24))                                   # t ~ 24s    privilege escalation
    events.append(_c2(28))                                        # t ~ 28s    C2
    return events


SCENARIOS = {
    "port_scan": port_scan,
    "ssh_brute_force": ssh_brute_force,
    "credential_compromise": credential_compromise,
    "web_attack": web_attack,
    "multi_stage_attack": multi_stage_attack,
}
