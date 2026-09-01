"""
GARUDA backend smoke test.

Phase "baseline": replays multi_stage_attack with the default (manual) response
policy and confirms the existing pipeline contract still holds — one incident
classified critical, mapped to 5 MITRE techniques, risk score 100 — and that
manual mode is still a pure no-op for the response engine (zero ActionLog rows).

Phase "auto": same scenario replay under an "auto" response policy. Confirms at
least one action gets auto-executed and logged (the early port-scan-stage
actions, before the incident's severity climbs past the default "high" ceiling).

Phase "hybrid": same scenario replay under a "hybrid" response policy. Confirms
a high-criticality action (isolate_host, targeting WEB01 — criticality "high"
in the seeded topology) lands in the pending-approval queue instead of
executing.

Each phase runs in its own subprocess against a freshly deleted garuda.db, so
scenario replays never bleed into each other via correlation (which would
otherwise merge a second run's events into the first run's incident, since
both use the same attacker/victim IPs).
"""
import os
import subprocess
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent


def _run_phase(phase: str):
    # Isolated scratch DB per phase — never touches a garuda.db a dev server has open.
    db_path = BACKEND_DIR / f"garuda_smoke_{phase}.db"
    if db_path.exists():
        os.remove(db_path)
    os.environ["GARUDA_DB_PATH"] = str(db_path)

    from app import models, response_engine
    from app.database import SessionLocal, init_db
    from app.pipeline import process_raw_event
    from app.scenarios.definitions import SCENARIOS

    init_db()
    db = SessionLocal()
    try:
        if phase in ("auto", "hybrid"):
            policy = response_engine.get_policy(db)
            policy.default_mode = phase
            db.commit()

        events = sorted(SCENARIOS["multi_stage_attack"](), key=lambda pair: pair[0])
        incident = None
        for _delay, raw in events:
            for message in process_raw_event(db, "scenario", raw):
                if message["type"] == "incident_update":
                    incident = message["data"]

        assert incident is not None, "no incident was correlated"
        assert incident["severity"] == "critical", f"expected critical severity, got {incident['severity']}"
        assert incident["risk_score"] == 100, f"expected risk score 100, got {incident['risk_score']}"
        assert len(incident["attack_techniques"]) == 5, (
            f"expected 5 MITRE techniques, got {len(incident['attack_techniques'])}"
        )
        print(f"[{phase}] baseline pipeline contract OK — critical / risk 100 / 5 techniques")

        actions = (
            db.query(models.ActionLog)
            .filter(models.ActionLog.incident_id == incident["incident_id"])
            .all()
        )

        if phase == "baseline":
            assert len(actions) == 0, f"manual mode should log zero actions, found {len(actions)}"
            print("[baseline] manual mode logged zero actions, as expected")

        elif phase == "auto":
            executed = [a for a in actions if a.status == "executed"]
            assert executed, "expected at least one auto-executed action in auto mode"
            print(f"[auto] {len(executed)} action(s) auto-executed and logged: {[a.action for a in executed]}")

        elif phase == "hybrid":
            pending = [a for a in actions if a.status == "pending"]
            assert pending, "expected at least one action in the pending-approval queue in hybrid mode"
            high_crit_pending = [a for a in pending if a.action in ("isolate_host", "disable_account", "kill_session")]
            assert high_crit_pending, (
                f"expected a high-criticality action pending approval, found pending: {[a.action for a in pending]}"
            )
            print(
                f"[hybrid] {len(pending)} action(s) pending approval, including high-criticality: "
                f"{[a.action for a in high_crit_pending]}"
            )
    finally:
        db.close()

    try:
        from app.database import engine

        engine.dispose()
        if db_path.exists():
            os.remove(db_path)
    except OSError:
        pass  # best-effort cleanup — a stale handle just means next run's pre-delete gets it

    print(f"[{phase}] PASSED\n")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        _run_phase(sys.argv[1])
    else:
        for phase_name in ("baseline", "auto", "hybrid"):
            result = subprocess.run([sys.executable, str(Path(__file__).resolve()), phase_name], cwd=BACKEND_DIR)
            if result.returncode != 0:
                print(f"Phase '{phase_name}' FAILED")
                sys.exit(result.returncode)
        print("All phases passed.")
