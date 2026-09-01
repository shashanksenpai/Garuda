# GARUDA

GARUDA is an agentic AI cybersecurity assistant that ingests security telemetry, correlates it into incidents, and runs it through an agentic investigation pipeline. Sample Mode, which replays predefined scenarios, and Live Mode, which would consume real Zeek, Suricata, or auth logs, both feed into the exact same pipeline. **Never add source-specific branching logic downstream of the normalization step** — preserving that single shared pipeline is a core architectural constraint of this project.

GARUDA also owns a simulated enterprise asset inventory + network topology (`app/scenarios/topology.py`) that the response engine, topology map, and packet flow view all operate against. **This is local demo infrastructure GARUDA owns — no code path in this project ever reaches a real firewall, IdP, cloud account, or production system.** Keep that boundary explicit in code comments and UI copy whenever touching `response_engine.py`, `assets.py`, or `packet_simulator.py`.

## Pipeline flow

A raw event comes in and is normalized into the common `Event` schema, then stored in the database. The rule engine runs detection against it, producing zero or more `Detection` records. Any detections are then correlated into an `Incident`, either merging into an existing one or creating a new one (this is also where `Incident.affected_assets` gets populated, by matching known IPs against the asset inventory). The LangGraph agent graph then runs an investigation on that incident, producing structured findings, a narrative summary, a risk score, and recommended response actions (both as prose and as a machine-actionable `structured_actions` list). `assets.py` then escalates the status of any affected assets, and `response_engine.py` executes, queues, or (in manual mode — the default) leaves alone each structured action per the active `ResponsePolicy`. Finally, updates are broadcast over SSE to the dashboard.

The single entry point for this entire flow is `process_raw_event` in `backend/app/pipeline.py`. Any new functionality should hook into this flow rather than duplicating it.

GARUDA can also run as a live multi-device exercise: `agent/garuda_agent.py` is a lightweight psutil-based collector participants run on their own laptops. It registers as a dynamic `Asset` (`is_dynamic=True`) and reports real local connections/processes/user as `source="agent"` events — normalized by `normalize_agent` and fed through the exact same pipeline as everything else, so detection (including the DoS-flood rule), correlation, and the response engine all work unmodified on real telemetry. Whenever a detection's source IP matches a dynamic asset, `live_agents.mark_attacker` auto-flags that laptop's `role` as `"attacker"` — this is how GARUDA "identifies the attacker" among connected devices, grounded in the same rule engine as everything else, not a guess. `agent.py attack` is a hard-capped (30s / 60conn-s) TCP-connect flood for demonstrating the DoS rule — real socket attempts, reported as real events, but rate/duration-capped so it can't meaningfully impact a target. Only meant to run against a consenting participant's own machine.

## Stack

- **Backend**: FastAPI + SQLAlchemy, SQLite for development at `backend/garuda.db` (swappable via `DATABASE_URL` in `app/config.py`). Pydantic handles schemas, LangGraph handles agent orchestration, reportlab generates PDF reports, sse-starlette handles the live SSE stream.
- **Frontend**: React + Vite, plain CSS with design tokens defined in `frontend/src/index.css` (no Tailwind), recharts for distribution charts, native `EventSource` API for the live feed (wrapped in `frontend/src/useLiveStream.js`).

## Backend structure

- `models.py` — SQLAlchemy models: `Event`, `Detection`, `Incident`, plus the simulated asset inventory (`Asset` — including the `is_dynamic`/`role`/`os_info`/`current_user`/`last_seen`/`processes` columns for real agent-reported laptops, `AssetEdge`, `BlockedIP`) and response engine state (`ResponsePolicy`, `ActionLog`).
- `schemas.py` — corresponding Pydantic response models. Every datetime field uses the `UtcDatetime` alias defined at the top of the file, not bare `datetime` — SQLite drops tzinfo on round-trip, so a naive value would serialize without a `Z`/offset suffix and get silently misparsed as local time by `new Date(...)` on the frontend. Keep using `UtcDatetime` for any new datetime field.
- `normalization.py` — converts a raw source dictionary into the common `Event` schema. Currently supports `zeek`, `suricata`, `auth`, `scenario`, and `agent` (real telemetry from `agent/garuda_agent.py`) sources.
- `detection.py` — the rule engine as a `RULES` list; new detection logic goes here. Includes a DoS-flood rule (`_detect_dos_flood`, high *volume* to one destination) distinct from the port-scan rule (`_detect_port_scan`, high *breadth* across distinct ports), and an unsupervised ML rule (`_detect_ml_anomaly`, last in `RULES`) layered on top — see `ml_detection.py`.
- `ml_detection.py` — self-calibrating `IsolationForest` (scikit-learn) scoring the same windowed connection-volume/breadth features the rules use (now including `established_ratio` and `common_web_port_ratio` — see `detection.py::_connection_outcome_stats`), fit on this session's own live traffic (no pre-existing labeled dataset). Module-global buffer/model behind a lock; cold-starts silent until `MIN_SAMPLES_TO_SCORE` (30) samples exist. Known tradeoff: it learns "normal" from whatever this session's traffic looks like, so a long-running attack scenario can eventually get absorbed into the baseline — accepted for a quick, dependency-light integration.
- `live_agents.py` — dynamic-asset bookkeeping for real GARUDA Agents: registration (idempotent by IP), heartbeat metadata, attacker-role escalation (`mark_attacker`), and the "connect a device" LAN-address helper. Doesn't touch the pipeline itself — connection telemetry an agent reports goes through `process_raw_event(db, "agent", raw)` like anything else.
- `correlation.py` — groups detections into incidents based on entity overlap, and populates `Incident.affected_assets` (in chronological order — the topology map's attack-path drawing depends on that order, so don't re-sort it alphabetically).
- `risk.py` — computes a 0–100 risk score and severity classification.
- `assets.py` — escalates affected-asset status (`healthy -> at_risk -> compromised`) after each investigation run; never downgrades an `isolated`/`blocked` asset (those are response-engine-owned).
- `response_engine.py` — decides execute/queue/skip for each recommended structured action per the active `ResponsePolicy` (manual/hybrid/auto, globally and per target-asset-criticality), runs the action registry (`block_ip`, `isolate_host`, `disable_account`, `kill_session`, `alert_soc`, `rate_limit`), and handles approve/reject/rollback. **manual mode is a complete no-op here** — identical to the original recommendations-only behavior.
- `packet_simulator.py` — synthesizes packet-level SSE events: one burst per real ingested `Event` (so the packet flow view shows the actual attack traffic shape), plus a continuous low-rate background "normal traffic" task started at app startup.
- `agents/`
  - `state.py` — shared `InvestigationState` TypedDict passed between graph nodes.
  - `log_analysis_agent.py` — turns detections into structured findings.
  - `threat_investigation_agent.py` — reconstructs the timeline into an evidence-backed narrative.
  - `response_agent.py` — turns findings into immediate/investigation/recovery prose **and** a `structured_actions` list (the machine-actionable mirror `response_engine.py` consumes — keep the two in lockstep).
  - `graph.py` — wires the agents together with LangGraph and exposes `run_investigation` as the entry point.
- `scenarios/`
  - `definitions.py` — `SCENARIOS` dictionary covering `port_scan`, `ssh_brute_force`, `credential_compromise`, `web_attack`, and `multi_stage_attack`.
  - `topology.py` — seeds the ~15-asset simulated enterprise topology (idempotent; no-ops if assets already exist). `WEB01`'s IP intentionally matches `definitions.py::VICTIM_IP`.
  - `player.py` — asynchronously replays a scenario through the pipeline in real time.
- `routers/` — `logs.py`, `live.py`, `events.py`, `incidents.py`, `status.py`, `topology.py` (topology read + `PATCH /assets/{id}` for manual role/criticality override), `actions.py`, `policy.py`, `agents.py` (`POST /register`, `POST /{id}/heartbeat`, `GET /connect-info`): ingestion, live mode control/streaming, read endpoints, the response engine's REST surface, and the live-agent surface.
- `sse.py` — simple pub/sub broadcaster for pushing messages to connected SSE clients. Message types now include `event`, `detection`, `incident_update`, `packet`, `asset_update`, `action_pending`, `action_executed`, `action_rejected`, `action_rolled_back`, `scenario_started`, `scenario_finished`.
- `report.py` — generates the PDF incident report (`build_incident_report_pdf`) and the Present-mode shareable markdown summary (`build_incident_markdown`) — both read the same `Incident` fields; don't fork a second data-assembly path for one of them.
- `main.py` — wires up the FastAPI app, CORS, all routers, and starts the packet simulator's background task on startup.

## Frontend structure

- `api.js` — fetch helpers that all go through the `/api` prefix, which Vite proxies to port 8123 in development.
- `useLiveStream.js` — the `EventSource` hook; automatically reconnects on drop.
- `App.jsx` — top-level state; merges incoming SSE messages into the incidents list, live event stream, topology, pending-actions queue, audit log, and a throttled packet buffer (flushed on a fixed interval — never re-render per raw SSE frame for packets).
- `components/` — `TopBar` (now also the Console/Topology view switch), `LiveEventStream`, `IncidentList`, `IncidentDetail` (has the "Present" button), `StatusCharts`, `RiskGauge`, `SeverityChip`, `BrandMark`, `NetworkTopologyMap`, `PacketFlow`, `ResponseConsole` (pending queue / policy settings / audit log), `FleetPanel` (connect-a-device helper + live connected-agents roster with manual role toggle), `PresentMode` (full-screen incident replay).
- `NetworkTopologyMap.jsx` in particular: node color = asset status via the severity tokens (`STATUS_COLOR`). Live packet dots are **not** SVG-per-edge animation (`ViewportPortal` isn't available in the installed reactflow 11.11.4, and an earlier per-edge-SMIL approach proved unreliable) — instead a manually viewport-transformed overlay (`useViewport()` + a plain absolutely-positioned layer) renders one CSS-keyframe-animated `.packet-dot` per packet, positioned by resolving src/dst IPs to node centers directly (no topology edge required — this is what makes traffic between two agent laptops with no predefined edge between them animate correctly). Each dot carries a `createdAt` and is safety-net-pruned on a timer, since `prefers-reduced-motion` means `onAnimationEnd` never fires. Hover cards need `.topo-map .react-flow__node { pointer-events: auto; }` — reactflow silently sets `pointer-events: none` on nodes with `draggable: false`, which kills hover unless overridden.

## Conventions to preserve carefully

- **Evidence-grounded agents**: the agents are intentionally deterministic and read only from stored `Detection` and `Incident` fields — they never invent evidence. If a real LLM call is wired in later, that same constraint must hold: findings and summaries must always trace back to actual database data.
- **No source-specific logic past normalize**: adding a new telemetry source means writing a new function in `normalization.py` and registering it in `NORMALIZERS` — nothing else should need to change.
- **New detection rules**: add a new function to `detection.py` and include it in `RULES`. It should return either a `Detection` or `None`, and use the existing `_already_detected` helper to avoid duplicate firing within a time window.
- **Correlation matches on the union of source and destination IPs**, not one-directional matching — a victim host's outbound C2 traffic makes it a source in a later stage of the same attack. This logic lives in `_entity_overlap` in `correlation.py` and should not be narrowed back to one-directional matching.
- **Response execution is policy-gated and scoped to the simulated asset inventory**: `response_agent.py` still only ever produces recommendations — it never executes anything itself. Whether a recommendation actually executes is entirely `response_engine.py`'s call, per the active `ResponsePolicy`: **manual** (default) is a full no-op, identical to the original "recommendations only" behavior; **hybrid** auto-executes only the reversible/low-risk actions (`block_ip`, `alert_soc`, `rate_limit`) and queues anything else that touches a high/critical-criticality asset for one-click approval; **auto** executes everything up to a configurable severity ceiling (always requiring approval above it, as a safety rail). Whatever the mode, every handler in `response_engine.py`'s `ACTION_REGISTRY` only mutates GARUDA's own `assets`/`blocked_ips`/`action_log` tables — never real infrastructure.
- **Severity color scale**: the `--sev-info` through `--sev-critical` variables in `index.css` are the core visual language of the dashboard. Any new severity-linked UI should reuse those variables rather than introducing new colors.

## Running the project

Backend (from `backend/`):
```bash
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8123
```

Frontend (from `frontend/`, in a separate terminal):
```bash
npm install
npm run dev
```

Frontend serves on `localhost:5173` and proxies `/api` calls to port 8123.

For a live multi-device exercise, bind the backend to all interfaces so LAN devices can reach it: `uvicorn app.main:app --host 0.0.0.0 --port 8123`. Then, from each participant's laptop (from `agent/`): `pip install -r requirements.txt && python garuda_agent.py join --server http://<host-ip>:8123`. The dashboard's Fleet panel (Topology & Response tab) shows a ready-to-copy version of that command with the host's actual LAN IP.

## Quick smoke test (no frontend needed)

`python backend/smoke_test.py` runs three phases (each in its own subprocess, against its own isolated scratch DB via the `GARUDA_DB_PATH` env var — never a `garuda.db` a dev server has open): **baseline** (default manual policy — confirms the original pipeline contract: one incident classified **critical**, five MITRE techniques, **risk score 100**, and zero `ActionLog` rows), **auto** (confirms at least one action auto-executes and is logged before the incident's severity climbs past the approval ceiling), and **hybrid** (confirms a high-criticality action like `isolate_host` lands in the pending-approval queue instead of executing). Run a single phase directly with `python backend/smoke_test.py <baseline|auto|hybrid>`.

## Extension points

- **Statistical/ML anomaly detection**: add new entries to `detection.py`'s `RULES` list, following the same `Detection` output contract as the existing rule-based checks.
- **Real Zeek/Suricata ingestion**: a log tailer just needs to call `POST /api/logs/upload` or import `process_raw_event` directly for each new line.
- **Swapping deterministic agents for real LLM calls**: keep this localized to files inside `agents/`; the graph wiring in `graph.py` and the shape of `InvestigationState` shouldn't need to change.
- **Moving to Postgres in production**: only requires changing `DATABASE_URL` in `app/config.py`.

## Gotchas

- `garuda.db` is development-only and gitignored — deleting it resets all state. If a dev server already has it open, don't delete it out from under a running process (SQLite file locking on Windows will error) — either stop the server first, or point tooling at an isolated file via the `GARUDA_DB_PATH` env var (see `smoke_test.py`).
- `EventSourceResponse` in `routers/live.py` expects the broadcaster to send raw JSON strings, not dictionaries. That message shape shouldn't change without also updating the `JSON.parse` call in `useLiveStream.js`.
- The scenario player uses wall-clock delays scaled by a speed multiplier, and its database calls are synchronous SQLAlchemy running inside an async task — keep event volumes small, or move the database work to a thread if that ever changes.
- A real laptop's ordinary background traffic (cloud sync, browser connections to many distinct ports/hosts, etc.) can look superficially like a port scan or DoS flood once agent telemetry is in the mix. `_detect_port_scan` and `_detect_dos_flood` (detection.py) mitigate this two ways: port-scan breadth is measured per destination host (real recon concentrates many ports on one target; a laptop running several independent services looks like many hosts with one port each, and no longer counts), and both rules skip firing when `_looks_like_benign_browsing` sees enough `Event.conn_status` evidence (ESTABLISHED handshakes, mostly to 80/443) to say the traffic is heavy legitimate use rather than a scan/flood. `conn_status` is only populated by sources that can observe it (the agent's psutil status, Zeek's `conn_state`); sources that can't (scenario replay, Suricata, the synthetic DoS-demo traffic from `agent.py attack`) are treated as having no evidence either way, so this never suppresses a real detection — only ambiguous cases where we have positive evidence of normal browsing.
- Any new datetime field must use `UtcDatetime` (see `schemas.py`), not bare `datetime` — see the note under Backend structure above.
