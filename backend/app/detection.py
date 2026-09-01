"""
Hybrid detection engine (rule layer). Statistical/anomaly detection can be added later
behind the same `run_detections` entry point without touching the rest of the pipeline.

Each rule inspects the *new* event plus a short recent window from the database, and
emits zero or more Detection rows. Detections are deliberately conservative about
duplicates: a rule will not refire the same (threat_type, source_ip, destination_ip)
tuple while an equivalent detection is still "fresh" (inside the same time window).
"""
from datetime import timedelta, timezone

from sqlalchemy import and_
from sqlalchemy.orm import Session

from . import config, models, mitre, ml_detection


def _to_utc(dt):
    """SQLite drops tzinfo on round-trip, so a freshly-queried Event's timestamp can
    come back naive while the just-created, still session-identity-mapped `event`
    parameter a rule receives stays timezone-aware — subtracting the two directly
    raises TypeError. Every _now()/_ts() in this codebase means UTC regardless of
    whether the value currently carries tzinfo, so normalize before any Python-level
    datetime arithmetic (DB-side >=/<= filtering isn't affected — SQLite compares the
    stored representations, not Python datetime objects)."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _recent(db: Session, **filters):
    q = db.query(models.Event)
    for k, v in filters.items():
        if v is not None:
            q = q.filter(getattr(models.Event, k) == v)
    return q


def _already_detected(db: Session, threat_type: str, source_ip: str, destination_ip: str | None, window_s: int) -> bool:
    cutoff = models.Event.timestamp  # placeholder to satisfy linters; not used directly
    from datetime import datetime, timezone

    since = datetime.now(timezone.utc) - timedelta(seconds=window_s)
    q = db.query(models.Detection).filter(
        models.Detection.threat_type == threat_type,
        models.Detection.source_ip == source_ip,
        models.Detection.timestamp >= since,
    )
    if destination_ip is not None:
        q = q.filter(models.Detection.destination_ip == destination_ip)
    return db.query(q.exists()).scalar()


# TCP handshake outcome, as reported by whichever source can see it: psutil connection
# status (agent) or Zeek's own conn_state (zeek conn.log). Sources that can't report it
# (scenario replay, Suricata alerts, the synthetic DoS-demo traffic in agent.py's `attack`
# command) leave conn_status None — which _connection_outcome_stats treats as "no
# evidence either way", so behavior for those sources is unchanged from before this field
# existed.
_ESTABLISHED_STATUSES = {
    "ESTABLISHED", "CLOSE_WAIT", "FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT", "CLOSING", "LAST_ACK",  # psutil
    "SF", "S1", "S2", "S3",  # Zeek conn_state: completed / normal termination
}
_UNESTABLISHED_STATUSES = {
    "SYN_SENT", "SYN_RECV",  # psutil: handshake never completed from this side
    "S0", "REJ", "RSTO", "RSTR", "RSTOS0", "RSTRH", "RSTOS1",  # Zeek: no reply / rejected / reset
}
_COMMON_WEB_PORTS = {80, 443}
_MIN_KNOWN_OUTCOMES = 5  # need at least this many conn_status-bearing connections before trusting the ratio


def _connection_outcome_stats(conns: list[models.Event]) -> tuple[float | None, float]:
    """(established_ratio, web_port_ratio) for a window of connections.

    established_ratio is None when fewer than _MIN_KNOWN_OUTCOMES connections report a
    known outcome — too little evidence to say anything, not evidence of anything."""
    known = [c for c in conns if c.conn_status and c.conn_status.upper() in (_ESTABLISHED_STATUSES | _UNESTABLISHED_STATUSES)]
    web_port_ratio = (sum(1 for c in conns if c.destination_port in _COMMON_WEB_PORTS) / len(conns)) if conns else 0.0
    if len(known) < _MIN_KNOWN_OUTCOMES:
        return None, web_port_ratio
    established_ratio = sum(1 for c in known if c.conn_status.upper() in _ESTABLISHED_STATUSES) / len(known)
    return established_ratio, web_port_ratio


def _looks_like_benign_browsing(conns: list[models.Event]) -> bool:
    """True only when we have real evidence (not just absence of evidence) that this
    window is mostly completed handshakes to ordinary web ports — the shape of heavy
    multi-tab browsing, not a scan or flood. A source that can't report conn_status
    never triggers this, so it can't suppress a scenario-replayed or Suricata-sourced
    attack, or the synthetic DoS-demo traffic from agent.py's `attack` command."""
    established_ratio, web_port_ratio = _connection_outcome_stats(conns)
    if established_ratio is None:
        return False
    return established_ratio >= 0.85 and web_port_ratio >= 0.7


def _make_detection(threat_type, confidence, severity, source_ip, destination_ip, evidence, technique_key, event_ids):
    tech = mitre.technique(technique_key)
    return models.Detection(
        threat_type=threat_type,
        confidence=confidence,
        severity=severity,
        source_ip=source_ip,
        destination_ip=destination_ip,
        evidence=evidence,
        mitre_technique_id=tech["id"],
        mitre_technique_name=tech["name"],
        event_ids=event_ids,
    )


def _detect_ssh_brute_force(db: Session, event: models.Event) -> models.Detection | None:
    if event.event_type != "auth_failure" or not event.source_ip:
        return None
    since = event.timestamp - timedelta(seconds=config.SSH_BRUTE_FORCE_WINDOW_SECONDS)
    fails = (
        _recent(db, event_type="auth_failure", source_ip=event.source_ip)
        .filter(models.Event.timestamp >= since, models.Event.timestamp <= event.timestamp)
        .all()
    )
    if len(fails) < config.SSH_BRUTE_FORCE_FAILS:
        return None
    if _already_detected(db, "SSH Brute Force", event.source_ip, event.destination_ip, config.SSH_BRUTE_FORCE_WINDOW_SECONDS):
        return None
    confidence = min(0.5 + 0.05 * len(fails), 0.98)
    evidence = (
        f"{len(fails)} authentication failures from {event.source_ip} against "
        f"{event.destination_ip or 'target host'} within {config.SSH_BRUTE_FORCE_WINDOW_SECONDS} seconds."
    )
    return _make_detection(
        "SSH Brute Force", confidence, "high", event.source_ip, event.destination_ip,
        evidence, "brute_force", [e.event_id for e in fails] + [event.event_id],
    )


def _detect_port_scan(db: Session, event: models.Event) -> models.Detection | None:
    """Real port scanning is breadth of ports probed against a narrow set of targets —
    not breadth of ports across many unrelated hosts, which is what an ordinary laptop
    running several independent services (browser, mail, cloud sync, chat, each on its
    own single port) looks like. So distinct-port breadth is measured per destination
    host, and the detection fires only once one host accounts for it on its own."""
    if event.event_type != "network_connection" or not event.source_ip:
        return None
    since = event.timestamp - timedelta(seconds=config.PORT_SCAN_WINDOW_SECONDS)
    conns = (
        _recent(db, event_type="network_connection", source_ip=event.source_ip)
        .filter(models.Event.timestamp >= since, models.Event.timestamp <= event.timestamp)
        .all()
    )
    by_dest: dict[str, list[models.Event]] = {}
    for c in conns:
        if c.destination_ip and c.destination_port is not None:
            by_dest.setdefault(c.destination_ip, []).append(c)
    if not by_dest:
        return None
    target_dest, target_conns = max(by_dest.items(), key=lambda kv: len({c.destination_port for c in kv[1]}))
    distinct_ports = {c.destination_port for c in target_conns}
    if len(distinct_ports) < config.PORT_SCAN_DISTINCT_PORTS:
        return None
    if _looks_like_benign_browsing(target_conns):
        return None  # mostly established handshakes to 80/443 — breadth from tabs, not recon
    if _already_detected(db, "Port Scan", event.source_ip, None, config.PORT_SCAN_WINDOW_SECONDS):
        return None
    evidence = (
        f"{event.source_ip} contacted {len(distinct_ports)} distinct ports on {target_dest} "
        f"within {config.PORT_SCAN_WINDOW_SECONDS} seconds, consistent with service discovery."
    )
    return _make_detection(
        "Port Scan", 0.8, "medium", event.source_ip, target_dest,
        evidence, "recon_port_scan", [c.event_id for c in target_conns],
    )


def _detect_dos_flood(db: Session, event: models.Event) -> models.Detection | None:
    """High *volume* of connections to the same destination in a short window — as
    opposed to _detect_port_scan's high *breadth* across distinct ports. Fires on
    repeated same-port floods (SYN floods, connect() floods, etc.), so it doesn't
    overlap with the port-scan rule."""
    if event.event_type != "network_connection" or not event.source_ip or not event.destination_ip:
        return None
    since = event.timestamp - timedelta(seconds=config.DOS_FLOOD_WINDOW_SECONDS)
    conns = (
        _recent(db, event_type="network_connection", source_ip=event.source_ip, destination_ip=event.destination_ip)
        .filter(models.Event.timestamp >= since, models.Event.timestamp <= event.timestamp)
        .all()
    )
    if len(conns) < config.DOS_FLOOD_CONNECTIONS:
        return None
    if _looks_like_benign_browsing(conns):
        return None  # mostly established handshakes to 80/443 — a busy CDN, not a flood
    if _already_detected(db, "Denial of Service Flood", event.source_ip, event.destination_ip, config.DOS_FLOOD_WINDOW_SECONDS):
        return None
    evidence = (
        f"{event.source_ip} opened {len(conns)} connections to {event.destination_ip} within "
        f"{config.DOS_FLOOD_WINDOW_SECONDS} seconds — consistent with a denial-of-service flood."
    )
    return _make_detection(
        "Denial of Service Flood", 0.9, "critical", event.source_ip, event.destination_ip,
        evidence, "dos", [c.event_id for c in conns],
    )


def _detect_credential_compromise(db: Session, event: models.Event) -> models.Detection | None:
    if event.event_type != "auth_success" or not event.source_ip:
        return None
    since = event.timestamp - timedelta(seconds=config.SSH_BRUTE_FORCE_WINDOW_SECONDS)
    fails = (
        _recent(db, event_type="auth_failure", source_ip=event.source_ip, destination_ip=event.destination_ip)
        .filter(models.Event.timestamp >= since, models.Event.timestamp <= event.timestamp)
        .all()
    )
    if len(fails) < config.SSH_BRUTE_FORCE_FAILS:
        return None
    if _already_detected(db, "Possible Credential Compromise", event.source_ip, event.destination_ip, config.SSH_BRUTE_FORCE_WINDOW_SECONDS):
        return None
    evidence = (
        f"Successful authentication from {event.source_ip} to {event.destination_ip} immediately "
        f"followed {len(fails)} prior failed attempts from the same source, indicating the "
        f"brute-force attempt may have succeeded."
    )
    return _make_detection(
        "Possible Credential Compromise", 0.85, "critical", event.source_ip, event.destination_ip,
        evidence, "valid_accounts", [e.event_id for e in fails] + [event.event_id],
    )


def _detect_privilege_escalation(db: Session, event: models.Event) -> models.Detection | None:
    if event.event_type != "privilege_escalation":
        return None
    evidence = event.message or "Privilege escalation event observed on host."
    return _make_detection(
        "Privilege Escalation", 0.75, "high", event.source_ip, event.destination_ip,
        evidence, "privilege_escalation", [event.event_id],
    )


def _detect_c2(db: Session, event: models.Event) -> models.Detection | None:
    if event.event_type != "suspicious_outbound":
        return None
    evidence = event.message or "Suspicious outbound communication following prior compromise indicators."
    return _make_detection(
        "Suspicious Outbound Communication", 0.7, "high", event.source_ip, event.destination_ip,
        evidence, "c2", [event.event_id],
    )


def _detect_web_attack(db: Session, event: models.Event) -> models.Detection | None:
    if event.event_type != "ids_alert" or event.source != "suricata":
        return None
    evidence = event.message or "IDS signature matched a known web attack pattern."
    return _make_detection(
        "Web Attack", 0.72, event.severity or "medium", event.source_ip, event.destination_ip,
        evidence, "web_attack", [event.event_id],
    )


def _detect_ml_anomaly(db: Session, event: models.Event) -> models.Detection | None:
    """Two independent ML layers, either of which can fire (see ml_detection.py):
    an unsupervised IsolationForest fit on this session's own live traffic, catching
    shapes that don't cross any single rule's fixed threshold but still look
    statistically unlike everything else this source (or session) has done; and, if
    an offline-trained artifact is present (see ../ml_training/), a supervised
    classifier trained on real-world attack traffic (CICIDS2017 by default), catching
    known attack shapes even if the session's own baseline has absorbed that pattern
    as normal — the unsupervised layer's documented blind spot. `technique_key=
    "ml_anomaly"` is intentionally absent from MITRE_TECHNIQUES — this fires on
    statistical/model deviation, not a matched technique, so mitre.technique()
    correctly falls back to id=None/name=None rather than forcing a guess at
    attribution."""
    if event.event_type != "network_connection" or not event.source_ip:
        return None
    since = event.timestamp - timedelta(seconds=config.ML_WINDOW_SECONDS)
    conns = (
        _recent(db, event_type="network_connection", source_ip=event.source_ip)
        .filter(models.Event.timestamp >= since, models.Event.timestamp <= event.timestamp)
        .order_by(models.Event.timestamp)
        .all()
    )
    if len(conns) < 3:
        return None  # not enough signal in this window to characterize a pattern

    distinct_ports = {c.destination_port for c in conns if c.destination_port is not None}
    distinct_dests = {c.destination_ip for c in conns if c.destination_ip}
    distinct_protocols = {c.protocol for c in conns if c.protocol}
    span_s = max((_to_utc(conns[-1].timestamp) - _to_utc(conns[0].timestamp)).total_seconds(), 1.0)
    established_ratio, web_port_ratio = _connection_outcome_stats(conns)
    features = [
        len(conns), len(distinct_ports), len(distinct_dests), len(distinct_protocols), len(conns) / span_s,
        established_ratio if established_ratio is not None else 0.5,  # 0.5 = "unknown", not "half established"
        web_port_ratio,
    ]

    result = ml_detection.observe_and_score(features)
    if result is None:
        return None
    if _already_detected(db, "Anomalous Network Behavior (ML)", event.source_ip, None, config.ML_WINDOW_SECONDS):
        return None

    supervised = result["supervised"]
    details = []
    if result["z_scores"] is not None:
        top_idx = max(range(len(features)), key=lambda i: abs(result["z_scores"][i]))
        top_name = ml_detection.FEATURE_NAMES[top_idx]
        details.append(
            f"deviates from this session's baseline, most unusual on {top_name} "
            f"({features[top_idx]:.1f} vs baseline ~{result['mean'][top_idx]:.1f}, "
            f"isolation-forest score {result['score']:.2f})"
        )
    if supervised is not None:
        details.append(
            f"matches known {supervised['label']} traffic shapes per the offline model trained on "
            f"real-world attack data ({supervised['probability']:.0%} confidence)"
        )
    evidence = (
        f"{event.source_ip}'s connection pattern over the last {config.ML_WINDOW_SECONDS}s "
        f"({len(conns)} connections, {len(distinct_ports)} distinct ports, {len(distinct_dests)} distinct "
        f"destinations) " + " and ".join(details) + "."
    )
    severity = "high" if (
        (result["score"] is not None and result["score"] < -0.15)
        or (supervised is not None and supervised["probability"] >= 0.85)
    ) else "medium"
    return _make_detection(
        "Anomalous Network Behavior (ML)", result["confidence"], severity, event.source_ip, None,
        evidence, "ml_anomaly", [c.event_id for c in conns],
    )


RULES = [
    _detect_ssh_brute_force,
    _detect_port_scan,
    _detect_dos_flood,
    _detect_credential_compromise,
    _detect_privilege_escalation,
    _detect_c2,
    _detect_web_attack,
    _detect_ml_anomaly,
]


def run_detections(db: Session, event: models.Event) -> list[models.Detection]:
    fired = []
    for rule in RULES:
        result = rule(db, event)
        if result is not None:
            db.add(result)
            fired.append(result)
    if fired:
        db.flush()
    return fired
