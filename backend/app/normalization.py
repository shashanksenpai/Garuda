"""
Converts events from any source (Zeek conn/dns/http/ssl/ssh logs, Suricata EVE JSON,
Linux auth logs, or the built-in scenario generator) into GARUDA's common event schema.

Every normalizer returns a plain dict matching the Event ORM columns. Missing fields
are left as None rather than raising, so the pipeline never breaks on a partial record.
"""
from datetime import datetime, timezone
from typing import Any


def _ts(value: Any) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return datetime.now(timezone.utc)
    return datetime.now(timezone.utc)


def normalize_zeek(raw: dict, log_type: str) -> dict:
    base = {
        "timestamp": _ts(raw.get("ts")),
        "source": "zeek",
        "source_ip": raw.get("id.orig_h") or raw.get("source_ip"),
        "destination_ip": raw.get("id.resp_h") or raw.get("destination_ip"),
        "source_port": raw.get("id.orig_p") or raw.get("source_port"),
        "destination_port": raw.get("id.resp_p") or raw.get("destination_port"),
        "protocol": (raw.get("proto") or raw.get("protocol") or "").upper() or None,
        "severity": "info",
        "raw_event_reference": raw,
    }
    if log_type == "conn":
        base["event_type"] = "network_connection"
        base["conn_status"] = raw.get("conn_state")  # Zeek's own handshake-outcome field (S0/SF/REJ/...)
        base["message"] = (
            f"Connection {base['source_ip']}:{base['source_port']} -> "
            f"{base['destination_ip']}:{base['destination_port']} ({base['protocol']})"
        )
    elif log_type == "dns":
        base["event_type"] = "dns_query"
        base["message"] = f"DNS query for {raw.get('query')}"
    elif log_type == "http":
        base["event_type"] = "http_request"
        base["message"] = f"HTTP {raw.get('method', 'GET')} {raw.get('uri', '/')}"
    elif log_type == "ssl":
        base["event_type"] = "tls_session"
        base["message"] = f"TLS session, SNI={raw.get('server_name')}"
    elif log_type == "ssh":
        base["event_type"] = "ssh_session"
        base["message"] = f"SSH session, auth_success={raw.get('auth_success')}"
    else:
        base["event_type"] = f"zeek_{log_type}"
        base["message"] = "Zeek event"
    return base


def normalize_suricata(raw: dict) -> dict:
    alert = raw.get("alert", {})
    severity_map = {1: "critical", 2: "high", 3: "medium"}
    return {
        "timestamp": _ts(raw.get("timestamp")),
        "source": "suricata",
        "event_type": "ids_alert",
        "source_ip": raw.get("src_ip"),
        "destination_ip": raw.get("dest_ip"),
        "source_port": raw.get("src_port"),
        "destination_port": raw.get("dest_port"),
        "protocol": raw.get("proto"),
        "severity": severity_map.get(alert.get("severity"), "medium"),
        "message": alert.get("signature", "Suricata alert"),
        "raw_event_reference": raw,
    }


def normalize_auth(raw: dict) -> dict:
    success = raw.get("result") == "success" or raw.get("success") is True
    return {
        "timestamp": _ts(raw.get("timestamp") or raw.get("ts")),
        "source": "auth",
        "event_type": "auth_success" if success else "auth_failure",
        "source_ip": raw.get("source_ip"),
        "destination_ip": raw.get("destination_ip") or raw.get("host_ip"),
        "username": raw.get("username"),
        "hostname": raw.get("hostname"),
        "process": "sshd",
        "severity": "info" if success else "low",
        "message": raw.get("message") or (
            f"Authentication {'succeeded' if success else 'failed'} for {raw.get('username')}"
        ),
        "raw_event_reference": raw,
    }


def normalize_scenario(raw: dict) -> dict:
    """Scenario events are already close to the common schema; this fills in defaults."""
    out = dict(raw)
    out["timestamp"] = _ts(raw.get("timestamp"))
    out.setdefault("source", "scenario")
    out.setdefault("severity", "info")
    out["raw_event_reference"] = raw
    return out


def normalize_agent(raw: dict) -> dict:
    """Real network_connection telemetry reported by a GARUDA Agent — the lightweight
    psutil-based collector friends run on their own laptops (see agent/garuda_agent.py).
    Unlike the other sources this is genuinely observed, not synthetic — the agent reports
    its own real connections, attributed to the real owning process/user where the OS
    permits it."""
    return {
        "timestamp": _ts(raw.get("timestamp")),
        "source": "agent",
        "event_type": raw.get("event_type", "network_connection"),
        "source_ip": raw.get("source_ip"),
        "destination_ip": raw.get("destination_ip"),
        "source_port": raw.get("source_port"),
        "destination_port": raw.get("destination_port"),
        "protocol": raw.get("protocol") or "TCP",
        "username": raw.get("username"),
        "hostname": raw.get("hostname"),
        "process": raw.get("process"),
        "conn_status": raw.get("conn_status"),
        "severity": raw.get("severity", "info"),
        "message": raw.get("message") or (
            f"{raw.get('source_ip')}:{raw.get('source_port')} -> "
            f"{raw.get('destination_ip')}:{raw.get('destination_port')} "
            f"({raw.get('process') or 'unknown process'})"
        ),
        "raw_event_reference": raw,
    }


NORMALIZERS = {
    "zeek": normalize_zeek,
    "suricata": normalize_suricata,
    "auth": normalize_auth,
    "scenario": normalize_scenario,
    "agent": normalize_agent,
}
