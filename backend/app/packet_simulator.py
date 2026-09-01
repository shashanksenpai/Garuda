"""
Dummy, but real-feeling, packet-level traffic for the topology map's live view.

Two sources, both broadcast over the same SSE channel as type "packet":

1. `synth_packets_for_event` — called from pipeline.py for every ingested Event
   (scenario or live). Synthesizes the handful of packets that would plausibly
   make up that event (a SYN scan probe, an SSH auth handshake, a C2 beacon
   burst, ...) so a viewer sees the actual attack traffic shape, not just the
   resulting alert. Deterministically tied to real event src/dst/ports — never
   invented topology.

2. `simulator` (a background asyncio task started at app startup) — generates
   low-rate "normal" traffic between topology nodes so the map feels alive
   even when no scenario is running. Independent of any real event.
"""
import asyncio
import random
from datetime import datetime, timezone

from . import models
from .sse import broadcaster

_COMMON_PORTS = [443, 443, 80, 53, 3389, 8080, 22, 445]
_PROTOCOLS = ["TCP", "TCP", "TCP", "UDP"]


def _packet(src_ip, src_port, dst_ip, dst_port, protocol, size, flags, severity, kind, label) -> dict:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": protocol,
        "size": size,
        "flags": flags,
        "severity": severity,
        "kind": kind,   # scenario | live | background
        "label": label,
    }


def synth_packets_for_event(event: models.Event) -> list[dict]:
    """Synthesizes the packet-level burst that would plausibly underlie one normalized
    Event, so the packet flow view shows real SYN-scan / brute-force / C2 shapes instead
    of just the derived alert. Returns [] for event types with no clear network correlate.

    Exception: "agent" events (real telemetry reported by agent/garuda_agent.py running on
    an actual friend's laptop) are already a real observed connection — passed through as
    exactly one real packet rather than embellished into a fabricated burst."""
    if not event.source_ip or not event.destination_ip:
        return []

    severity = event.severity or "info"
    src, dst = event.source_ip, event.destination_ip
    sport = event.source_port or random.randint(1024, 65000)

    if event.source == "agent":
        return [_packet(src, event.source_port, dst, event.destination_port, event.protocol or "TCP",
                         random.randint(64, 1500), "SYN", severity, "agent", event.event_type)]

    kind = "scenario" if event.source == "scenario" else "live"

    if event.event_type == "network_connection":
        return [_packet(src, sport, dst, event.destination_port, event.protocol or "TCP",
                         random.randint(60, 1500), "SYN", severity, kind, "recon_probe")]

    if event.event_type in ("auth_failure", "auth_success"):
        flags = "PSH,ACK" if event.event_type == "auth_success" else "RST"
        return [
            _packet(src, sport, dst, 22, "TCP", random.randint(64, 200), "SYN", severity, kind, "ssh_auth"),
            _packet(src, sport, dst, 22, "TCP", random.randint(80, 300), flags, severity, kind, "ssh_auth"),
        ]

    if event.event_type == "suspicious_outbound":
        return [
            _packet(src, sport, dst, event.destination_port or 4444, event.protocol or "TCP",
                    random.randint(200, 900), "PSH,ACK", severity, kind, "c2_beacon")
            for _ in range(3)
        ]

    if event.event_type == "ids_alert":
        return [
            _packet(src, sport, dst, event.destination_port or 80, event.protocol or "TCP",
                    random.randint(300, 1400), "PSH,ACK", severity, kind, "web_attack")
            for _ in range(2)
        ]

    return []


class PacketSimulator:
    """Background 'normal traffic' generator — continuous, low-rate, independent of
    whatever scenario (if any) is currently playing."""

    def __init__(self):
        self._task: asyncio.Task | None = None

    def start(self):
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run())

    def stop(self):
        if self._task is not None:
            self._task.cancel()
            self._task = None

    async def _run(self):
        from .database import SessionLocal

        db = SessionLocal()
        try:
            edges = db.query(models.AssetEdge).all()
            assets = {a.asset_id: a for a in db.query(models.Asset).all()}
        finally:
            db.close()

        pairs = []
        for e in edges:
            s, t = assets.get(e.source_asset_id), assets.get(e.target_asset_id)
            if s and t and s.ip_address and t.ip_address:
                pairs.append((s, t))
        if not pairs:
            return

        try:
            while True:
                await asyncio.sleep(random.uniform(0.4, 0.9))
                a, b = random.choice(pairs)
                src, dst = (a, b) if random.random() < 0.5 else (b, a)
                packet = _packet(
                    src.ip_address, random.randint(1024, 65000),
                    dst.ip_address, random.choice(_COMMON_PORTS),
                    random.choice(_PROTOCOLS), random.randint(64, 1500),
                    "ACK", "info", "background", "normal_traffic",
                )
                await broadcaster.publish("packet", packet)
        except asyncio.CancelledError:
            pass


simulator = PacketSimulator()
