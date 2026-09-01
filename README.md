# GARUDA — Agentic AI Cybersecurity Assistant

A working prototype for real-time-style security telemetry ingestion, correlation,
and agentic threat investigation. Sample Mode and Live Mode share one pipeline:

```
raw event (zeek/suricata/auth/scenario/agent)
  -> normalize (common event schema)
  -> detect (rule engine)
  -> correlate (group into incidents)
  -> LangGraph agents: Log Analysis -> Threat Investigation -> Response
  -> risk score
  -> SSE push to dashboard
```

`agent` events come from real laptops running `agent/garuda_agent.py` — see
[Live multi-device exercise](#live-multi-device-exercise-real-laptops) below.

## Structure

```
backend/    FastAPI + SQLAlchemy (SQLite) + LangGraph agents + response engine
            + packet simulator + reportlab PDF report
frontend/   React (Vite) dashboard — SSE live feed, incident detail, recharts,
            reactflow topology map, response console, full-screen present mode
```

## Run the backend

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8123
```

This creates `garuda.db` (SQLite) on first run — no external DB needed for the demo.
Swap `DATABASE_URL` in `app/config.py` for Postgres in production.

## Run the frontend

```bash
cd frontend
npm install
npm run dev
```

Opens on http://localhost:5173 and proxies `/api/*` to the backend on port 8123
(see `vite.config.js`).

## Demo it

1. Start both servers above.
2. Open the dashboard. Pick a scenario in the top bar (`multi_stage_attack` is the
   full recon -> brute force -> login -> privesc -> C2 chain) and click **Run scenario**.
3. Watch the live event stream populate, a correlated incident appear, its risk
   score climb, and the AI investigation + response recommendations fill in.
4. Open the incident and click **Download incident report (PDF)**, or **Present**
   for a full-screen replay of the incident with a "Copy shareable summary" button.
5. Switch to the **Topology & Response** tab to see the simulated enterprise
   network, live packet flow, and (once you switch the response policy to
   hybrid/auto) the pending-approval queue and audit log fill in as the
   response engine reacts to the scenario.

## Live multi-device exercise (real laptops)

Beyond replayed scenarios, GARUDA can run as a live exercise across real machines
on your LAN, with participants posing as the enterprise and/or an attacker.

1. Start the backend reachable on your LAN: `uvicorn app.main:app --host 0.0.0.0 --port 8123`.
2. On each participant's laptop: `cd agent && pip install -r requirements.txt`,
   then `python garuda_agent.py join --server http://<host-ip>:8123 --name "Your-Laptop"`.
   The dashboard's **Fleet panel** (Topology & Response tab) shows this command
   pre-filled with the host's actual LAN IP — just copy it.
3. Each joined laptop shows up as a live node on the topology map immediately,
   with its real IP, logged-in user, OS, and a snapshot of local processes visible
   on hover — no admin/root required (it uses `psutil`, not packet capture).
4. To demonstrate a DoS attack: `python garuda_agent.py attack --server <url> --target <their-ip>`
   from a laptop whose owner has agreed to take part. This is a hard-capped
   (30s max, 60 connections/sec max) TCP-connect flood — real socket attempts,
   reported as real events — not a real denial-of-service tool. GARUDA detects
   the flood (`Denial of Service Flood`, MITRE T1498) and **automatically flags
   the attacking laptop's role as "attacker"** on the topology map, based purely
   on its behavior — no one has to declare it. Roles can also be set manually
   from the Fleet panel.
5. Malicious traffic (from a recently-detected source) renders as larger, glowing
   red dots on the topology map and highlighted rows in the packet flow table,
   distinct from ordinary background/enterprise traffic.

Everything an agent reports is visible only to the GARUDA server it's pointed at.
Only run `attack` mode against a machine whose owner has agreed to take part.

## Feeding real telemetry instead of Sample Mode

`POST /api/logs/upload` with `{"source": "zeek"|"suricata"|"auth", "log_type": "...", "events": [...]}`
runs raw events through the exact same pipeline (`app/pipeline.py::process_raw_event`).
A real Zeek/Suricata log tailer just needs to call that endpoint (or import
`process_raw_event` directly) per new line — no other code changes required, per the
"live and sample mode share one pipeline" architecture principle.

## Notes on scope

- The three required agents (Log Analysis, Threat Investigation, Response) are
  implemented as deterministic, evidence-grounded LangGraph nodes rather than
  live LLM calls, so the demo has zero external dependencies or API-key
  requirements and is fully reproducible. Each node's output is built directly
  from stored detections/timeline data — never invented — which is the
  "evidence-backed, not hallucinated" requirement from the spec. Swapping any
  node for a real LLM call (e.g. via the Anthropic API) is a localized change
  in `app/agents/*.py` — the graph wiring and shared state don't need to change.
- Detection is rule-based (SSH brute force, port scan, DoS flood, credential
  compromise, privilege escalation, suspicious outbound/C2, IDS/web-attack
  alerts). A statistical/ML anomaly layer can be added as additional entries
  in `app/detection.py::RULES` without touching correlation, risk, or agents.
- By default GARUDA only recommends response actions — nothing executes
  automatically, per the spec's human-in-the-loop requirement. A response
  policy (`GET`/`PUT /api/policy`, or the Topology & Response console)
  can switch this to **hybrid** (low-risk actions auto-execute; anything
  touching a high/critical-criticality asset queues for one-click approval)
  or **auto** (everything executes up to a configurable severity ceiling,
  above which approval is always required). Every response action is scoped
  to GARUDA's own simulated asset inventory (`app/scenarios/topology.py`) —
  no code path reaches real infrastructure. See `app/response_engine.py`.
