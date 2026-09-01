"""
Trains a supervised classifier on the windowed features prepare_dataset.py produces,
and exports it for ml_detection.py to load alongside the existing self-calibrating
IsolationForest. See README.md for the full pipeline.

The metric that matters here isn't overall accuracy — it's the false-positive rate on
the benign class, specifically for windows that look like heavy multi-tab browsing
(many connections, high established_ratio, high common_web_port_ratio). That's the
exact failure mode this model exists to fix, so it's reported separately.

Usage:
    python train_model.py --data data/processed/windows.csv --out ../app/ml/anomaly_model_v1.joblib
"""
import argparse
import os
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

FEATURE_NAMES = [
    "connections", "distinct_ports", "distinct_destinations", "distinct_protocols", "connections_per_second",
    "established_ratio", "common_web_port_ratio",
]


def split_by_day(df: pd.DataFrame, test_days: list[str]):
    """Splits by source CSV file (day/scenario) rather than random shuffle — flows
    within the same day/attack run are highly correlated, so a random split would leak
    the test set's own patterns into training and overstate accuracy."""
    test_mask = df["day_file"].isin(test_days)
    if not test_mask.any():
        available = sorted(df["day_file"].unique())
        raise SystemExit(f"none of --test-days {test_days} found. Available day_file values: {available}")
    return df[~test_mask], df[test_mask]


def benign_browsing_false_positive_rate(model, df: pd.DataFrame) -> float | None:
    """Precision on the specific slice this model was built to fix: benign windows
    with heavy connection volume, mostly-established handshakes, mostly on 80/443 —
    the shape of several browser tabs loading at once."""
    browsing_like = df[
        (df["label"] == "benign")
        & (df["connections"] >= 10)
        & (df["established_ratio"] >= 0.85)
        & (df["common_web_port_ratio"] >= 0.7)
    ]
    if browsing_like.empty:
        return None
    preds = model.predict(browsing_like[FEATURE_NAMES])
    return float((preds != "benign").mean())


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", default="data/processed/windows.csv")
    ap.add_argument("--out", default="../app/ml/anomaly_model_v1.joblib")
    ap.add_argument("--test-days", nargs="+", default=None,
                     help="day_file value(s) to hold out for testing, e.g. Friday-WorkingHours.pcap_ISCX.csv. "
                          "Defaults to the last day_file alphabetically if omitted.")
    args = ap.parse_args()

    df = pd.read_csv(args.data)
    missing_cols = [c for c in FEATURE_NAMES if c not in df.columns]
    if missing_cols:
        raise SystemExit(f"{args.data} is missing expected columns {missing_cols} — was it built by prepare_dataset.py?")

    test_days = args.test_days or [sorted(df["day_file"].unique())[-1]]
    train_df, test_df = split_by_day(df, test_days)
    print(f"train: {len(train_df)} windows from {sorted(train_df['day_file'].unique())}")
    print(f"test:  {len(test_df)} windows from {sorted(test_df['day_file'].unique())}")

    model = RandomForestClassifier(n_estimators=300, max_depth=12, class_weight="balanced", random_state=42, n_jobs=-1)
    model.fit(train_df[FEATURE_NAMES], train_df["label"])

    preds = model.predict(test_df[FEATURE_NAMES])
    print("\n=== classification report (test days) ===")
    print(classification_report(test_df["label"], preds))
    print("=== confusion matrix ===")
    labels = sorted(df["label"].unique())
    print(pd.DataFrame(confusion_matrix(test_df["label"], preds, labels=labels), index=labels, columns=labels))

    fp_rate = benign_browsing_false_positive_rate(model, test_df)
    print("\n=== benign multi-tab-browsing-shaped false positive rate ===")
    print("n/a — no matching windows in test set" if fp_rate is None else f"{fp_rate:.1%}")

    print("\n=== feature importances ===")
    for name, importance in sorted(zip(FEATURE_NAMES, model.feature_importances_), key=lambda x: -x[1]):
        print(f"  {name:<24} {importance:.3f}")

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    artifact = {
        "model": model,
        "feature_names": FEATURE_NAMES,
        "classes": list(model.classes_),
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "version": "v1",
    }
    joblib.dump(artifact, args.out)
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
