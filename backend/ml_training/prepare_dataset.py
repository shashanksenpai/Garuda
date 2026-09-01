"""
Turns raw CICIDS2017 per-day flow CSVs into GARUDA's own windowed feature space —
the same (connections, distinct_ports, distinct_destinations, distinct_protocols,
connections_per_second, established_ratio, common_web_port_ratio) vector detection.py
computes at detection time (see FEATURE_NAMES in ../app/ml_detection.py). Training on
raw CICFlowMeter output directly wouldn't transfer: GARUDA's agent only ever sees
flow-level metadata (no packet capture), so a model needs to be trained on the same
reduced feature space it will run on.

Usage:
    python prepare_dataset.py --raw-dir data/raw --out data/processed/windows.csv

Expects one or more of CICIDS2017's per-day CSVs (the "GeneratedLabelledFlows" /
"MachineLearningCVE" release — the variant that keeps Source IP/Destination IP/
Timestamp columns; some redistributions strip these for anonymization and won't work
here, since per-source windowing is the whole point) in --raw-dir. See README.md for
where to get them.
"""
import argparse
import glob
import os
import re
import sys

import pandas as pd

WINDOW_SECONDS_DEFAULT = 120
COMMON_WEB_PORTS = {80, 443}

# CICIDS2017 CSVs across mirrors disagree on exact column spelling/whitespace
# (" Destination Port" vs "Destination Port" vs "dst_port"). Match case/whitespace-
# insensitively and take the first candidate present.
_COLUMN_CANDIDATES = {
    "source_ip": ["source ip", "src ip", "srcip"],
    "destination_ip": ["destination ip", "dst ip", "dstip"],
    "destination_port": ["destination port", "dst port", "dstport"],
    "protocol": ["protocol"],
    "timestamp": ["timestamp"],
    "label": ["label"],
    "total_bwd_packets": ["total backward packets", "tot bwd pkts"],
    "syn_flag_count": ["syn flag count", "syn flag cnt"],
    "ack_flag_count": ["ack flag count", "ack flag cnt"],
    "rst_flag_count": ["rst flag count", "rst flag cnt"],
}


def _normalize_columns(df: pd.DataFrame) -> dict[str, str]:
    """Maps our canonical field names -> this file's actual column names."""
    lookup = {c.strip().lower(): c for c in df.columns}
    resolved = {}
    for field, candidates in _COLUMN_CANDIDATES.items():
        for cand in candidates:
            if cand in lookup:
                resolved[field] = lookup[cand]
                break
    return resolved


def _flow_is_established(row, cols) -> bool | None:
    """Proxy for a completed TCP handshake from CICFlowMeter's flag/packet columns —
    there's no direct 'connection status' field in this dataset. A flow that got zero
    backward packets and no ACK back (just a SYN out) never completed a handshake,
    matching psutil's SYN_SENT / Zeek's S0. Anything else with backward traffic and no
    reset is treated as established. Returns None (unknown) if the needed columns
    aren't present in this CSV, matching detection.py's own "no evidence" semantics."""
    if "total_bwd_packets" not in cols:
        return None
    try:
        bwd_packets = float(row[cols["total_bwd_packets"]])
    except (ValueError, TypeError):
        return None
    if "rst_flag_count" in cols:
        try:
            if float(row[cols["rst_flag_count"]]) > 0:
                return False
        except (ValueError, TypeError):
            pass
    return bwd_packets > 0


def _classify_label(raw_label: str) -> str:
    label = (raw_label or "").strip().lower()
    if label in ("benign", ""):
        return "benign"
    if "portscan" in label or "port scan" in label:
        return "portscan"
    if "dos" in label or "ddos" in label:  # covers Hulk/GoldenEye/Slowloris/Slowhttptest/DDoS
        return "dos"
    return "other_attack"  # brute force, web attack, infiltration, botnet, etc. — not our target classes


def load_raw(raw_dir: str) -> pd.DataFrame:
    paths = sorted(glob.glob(os.path.join(raw_dir, "*.csv")))
    if not paths:
        sys.exit(f"No CSV files found in {raw_dir} — see README.md for how to get the CICIDS2017 flow CSVs.")
    frames = []
    for path in paths:
        df = pd.read_csv(path, low_memory=False, encoding="latin1")
        cols = _normalize_columns(df)
        missing = [f for f in ("source_ip", "destination_ip", "destination_port", "timestamp", "label") if f not in cols]
        if missing:
            print(f"skipping {os.path.basename(path)}: missing required column(s) {missing} "
                  f"(this looks like an anonymized/reduced CSV variant without IP/timestamp columns)")
            continue
        df["_day_file"] = os.path.basename(path)
        df["_source_ip"] = df[cols["source_ip"]]
        df["_destination_ip"] = df[cols["destination_ip"]]
        df["_destination_port"] = pd.to_numeric(df[cols["destination_port"]], errors="coerce")
        df["_protocol"] = df[cols["protocol"]] if "protocol" in cols else None
        df["_timestamp"] = pd.to_datetime(df[cols["timestamp"]], dayfirst=True, errors="coerce")
        df["_label_class"] = df[cols["label"]].map(_classify_label)
        df["_established"] = df.apply(lambda r: _flow_is_established(r, cols), axis=1)
        frames.append(df[["_day_file", "_source_ip", "_destination_ip", "_destination_port", "_protocol",
                           "_timestamp", "_label_class", "_established"]])
    if not frames:
        sys.exit("No usable CSVs (all were missing required columns) — see README.md.")
    combined = pd.concat(frames, ignore_index=True)
    combined = combined.dropna(subset=["_source_ip", "_timestamp"])
    return combined


def window_features(df: pd.DataFrame, window_seconds: int) -> pd.DataFrame:
    df = df.sort_values("_timestamp")
    df["_bucket"] = df["_timestamp"].dt.floor(f"{window_seconds}s")

    rows = []
    for (day_file, source_ip, bucket), group in df.groupby(["_day_file", "_source_ip", "_bucket"]):
        n = len(group)
        if n < 3:
            continue  # matches detection.py's own "not enough signal" floor
        distinct_ports = group["_destination_port"].dropna().nunique()
        distinct_dests = group["_destination_ip"].nunique()
        span_s = max((group["_timestamp"].max() - group["_timestamp"].min()).total_seconds(), 1.0)

        known = group["_established"].dropna()
        established_ratio = float(known.mean()) if len(known) >= 5 else 0.5  # 0.5 = "unknown", matches detection.py
        web_port_ratio = float(group["_destination_port"].isin(COMMON_WEB_PORTS).mean())

        labels_present = set(group["_label_class"])
        if "dos" in labels_present:
            label = "dos"
        elif "portscan" in labels_present:
            label = "portscan"
        elif "other_attack" in labels_present:
            continue  # not one of our two target classes — drop rather than mislabel as benign
        else:
            label = "benign"

        rows.append({
            "day_file": day_file,
            "source_ip": source_ip,
            "window_start": bucket,
            "connections": n,
            "distinct_ports": distinct_ports,
            "distinct_destinations": distinct_dests,
            "distinct_protocols": group["_protocol"].nunique() if group["_protocol"].notna().any() else 1,
            "connections_per_second": n / span_s,
            "established_ratio": established_ratio,
            "common_web_port_ratio": web_port_ratio,
            "label": label,
        })
    return pd.DataFrame(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--raw-dir", default="data/raw")
    ap.add_argument("--out", default="data/processed/windows.csv")
    ap.add_argument("--window-seconds", type=int, default=WINDOW_SECONDS_DEFAULT)
    args = ap.parse_args()

    raw = load_raw(args.raw_dir)
    windows = window_features(raw, args.window_seconds)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    windows.to_csv(args.out, index=False)
    print(f"wrote {len(windows)} windows to {args.out}")
    print(windows["label"].value_counts())


if __name__ == "__main__":
    main()
