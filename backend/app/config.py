import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
# GARUDA_DB_PATH lets tooling (e.g. smoke_test.py) point at an isolated scratch
# database without disturbing a `garuda.db` a dev server already has open.
DB_PATH = Path(os.environ.get("GARUDA_DB_PATH") or (BASE_DIR / "garuda.db"))
DATABASE_URL = f"sqlite:///{DB_PATH}"

# Correlation window: events within this many seconds of each other,
# sharing an entity (IP/host/user), are considered candidates for the same incident.
CORRELATION_WINDOW_SECONDS = 300

# Detection thresholds
SSH_BRUTE_FORCE_FAILS = 5
SSH_BRUTE_FORCE_WINDOW_SECONDS = 120
PORT_SCAN_DISTINCT_PORTS = 8
PORT_SCAN_WINDOW_SECONDS = 60

# A DoS flood is high *volume* to the same destination (as opposed to a port scan's
# high *breadth* across distinct ports) in a short window.
DOS_FLOOD_CONNECTIONS = 30
DOS_FLOOD_WINDOW_SECONDS = 8

# A dynamic (agent-reported) asset is considered offline in the UI once its last
# heartbeat is older than this.
AGENT_STALE_SECONDS = 15

# Window used to build the per-source feature vector for the ML anomaly rule
# (detection.py::_detect_ml_anomaly / ml_detection.py).
ML_WINDOW_SECONDS = 120
