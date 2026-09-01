"""
Unsupervised behavioral-anomaly scoring, layered on top of the same windowed
connection-volume/breadth features the rule-based checks in detection.py use.
Catches patterns that don't cross any single fixed threshold but still look
statistically unlike this session's own traffic — a complement to the rules, not
a replacement for them.

There's no pre-existing labeled attack dataset here (this is a live demo, not a
production SOC with historical incident data), so the model is self-calibrating:
a small IsolationForest is fit directly on this session's own recent traffic and
periodically refit as more arrives. "Normal" is whatever this session's traffic
mostly looks like — which also means running an obvious attack scenario for long
enough will eventually teach the model that pattern is normal too. That's an
accepted tradeoff for a quick, dependency-light integration, not an oversight.
"""
import threading
from collections import deque
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest

MIN_SAMPLES_TO_SCORE = 30  # cold start: need a baseline before anything can look unusual against it
MAX_BUFFER = 500
REFIT_EVERY = 10  # re-fit after this many new samples since the last fit

FEATURE_NAMES = [
    "connections", "distinct_ports", "distinct_destinations", "distinct_protocols", "connections_per_second",
    "established_ratio", "common_web_port_ratio",
]

# Offline-trained classifier on real-world attack traffic (see ../ml_training/), loaded
# once if present. Optional by design: until someone runs that pipeline, this path is a
# no-op and behavior is exactly the pure self-calibrating IsolationForest below.
SUPERVISED_MODEL_PATH = Path(__file__).resolve().parent / "ml" / "anomaly_model_v1.joblib"
SUPERVISED_CONFIDENCE_THRESHOLD = 0.7

_lock = threading.Lock()
_buffer: deque = deque(maxlen=MAX_BUFFER)
_model: IsolationForest | None = None
_since_refit = 0

_supervised = None  # {"model", "feature_names", "classes", ...} or None once load is attempted
_supervised_load_attempted = False


def _load_supervised():
    global _supervised, _supervised_load_attempted
    if _supervised_load_attempted:
        return _supervised
    _supervised_load_attempted = True
    if SUPERVISED_MODEL_PATH.exists():
        import joblib
        try:
            artifact = joblib.load(SUPERVISED_MODEL_PATH)
            if artifact.get("feature_names") == FEATURE_NAMES:
                _supervised = artifact
            else:
                print(f"[ml_detection] ignoring {SUPERVISED_MODEL_PATH}: trained on a different feature set "
                      f"({artifact.get('feature_names')}) than the live feature vector ({FEATURE_NAMES})")
        except Exception as exc:
            print(f"[ml_detection] failed to load {SUPERVISED_MODEL_PATH}: {exc}")
    return _supervised


def _score_supervised(features: list[float]) -> dict | None:
    """Independent check against the offline-trained model, if one is loaded. Fires
    only above SUPERVISED_CONFIDENCE_THRESHOLD on a non-benign class — this is meant to
    catch known real-world attack shapes the session's own IsolationForest baseline may
    have absorbed as normal (its documented long-running-attack blind spot), not to
    second-guess every borderline case."""
    supervised = _load_supervised()
    if supervised is None:
        return None
    model = supervised["model"]
    proba = model.predict_proba([features])[0]
    classes = model.classes_
    top_idx = int(np.argmax(proba))
    label, probability = classes[top_idx], float(proba[top_idx])
    if label == "benign" or probability < SUPERVISED_CONFIDENCE_THRESHOLD:
        return None
    return {"label": label, "probability": probability}


def _refit_locked():
    global _model
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    model.fit(np.array(_buffer))
    _model = model


def observe_and_score(features: list[float]) -> dict | None:
    """Records this feature vector into the rolling baseline, then scores it two ways:
    against the session's own self-calibrating IsolationForest (once there's enough
    history for a baseline), and — independently, if a trained artifact is present —
    against the offline supervised model. Either can fire on its own; the supervised
    path exists specifically to catch known attack shapes the session's own baseline
    may have absorbed as normal. Returns None when neither fires; otherwise a dict
    with the anomaly score/confidence, per-feature baseline stats for human-readable
    evidence (never invents a reason — always traces back to these numbers), which
    detector(s) fired, and the supervised model's own label/probability if it fired."""
    global _since_refit

    with _lock:
        _buffer.append(features)
        _since_refit += 1
        have_baseline = len(_buffer) >= MIN_SAMPLES_TO_SCORE
        if have_baseline and (_model is None or _since_refit >= REFIT_EVERY):
            _refit_locked()
            _since_refit = 0

        score = mean = std = None
        unsupervised_flagged = False
        if have_baseline and _model is not None:
            X = np.array(_buffer)
            mean = X.mean(axis=0)
            std = X.std(axis=0)
            arr = np.array([features])
            unsupervised_flagged = int(_model.predict(arr)[0]) == -1
            score = float(_model.decision_function(arr)[0])

    supervised = _score_supervised(features)
    if not unsupervised_flagged and supervised is None:
        return None

    z_scores = mean_list = None
    if mean is not None:
        std_safe = np.where(std == 0, 1.0, std)
        z_scores = ((np.array(features) - mean) / std_safe).tolist()
        mean_list = mean.tolist()

    if unsupervised_flagged and supervised is not None:
        fired_by = "both"
        confidence = round(max(min(0.5 + max(0.0, -score) * 2, 0.95), supervised["probability"]), 2)
    elif unsupervised_flagged:
        fired_by = "unsupervised"
        confidence = round(min(0.5 + max(0.0, -score) * 2, 0.95), 2)
    else:
        fired_by = "supervised"
        confidence = round(supervised["probability"], 2)

    return {
        "score": score, "confidence": confidence, "z_scores": z_scores, "mean": mean_list,
        "supervised": supervised, "fired_by": fired_by,
    }
