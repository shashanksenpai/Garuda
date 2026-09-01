# GARUDA ML training pipeline

Offline pipeline for training a supervised anomaly classifier on real-world attack
traffic, to run alongside (not replace) the self-calibrating `IsolationForest` in
`../app/ml_detection.py`. Nothing here runs as part of the live app — it's a one-time
(or occasional-retrain) job whose only output the app consumes is
`../app/ml/anomaly_model_v1.joblib`.

## Why CICIDS2017

GARUDA's agent (`agent/garuda_agent.py`) only ever reports flow-level metadata via
psutil — source/destination IP and port, protocol, process, connection status. No
packet capture, no byte counts, no TCP flags. That constrains which dataset is usable:
we need one whose classes we care about (port scan, DoS) can be reduced to that same
feature space, not one that requires payload-level features we can't produce at
inference time.

[CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) (Canadian Institute for
Cybersecurity) fits: it has labeled PortScan and DoS traffic (Hulk/GoldenEye/Slowloris/
Slowhttptest), and — critically — its **Benign** class is captured from real user
activity including ordinary web browsing. That's the exact negative example this model
needs: without real "several tabs open" traffic in the training data, a model has no
way to learn that shape is normal.

Skip NSL-KDD/KDD'99 for this — it's 1999-era traffic and won't teach the model
anything about modern TLS/CDN-heavy browsing, which is the specific pattern causing
false positives here.

## Getting the data

Automated download isn't currently available — the historical direct-download paths
under `cicresearch.ca` and the old `205.174.165.80` mirror now redirect back to the UNB
[dataset landing page](https://www.unb.ca/cic/datasets/ids-2017.html) instead of
serving the file. Get it manually:

1. Go to https://www.unb.ca/cic/datasets/ids-2017.html and follow their current
   download link (labeled "Download this dataset" as of this writing).
2. You want the **flow CSVs**, not the raw pcaps — look for `GeneratedLabelledFlows.zip`
   or `MachineLearningCVE`/`MachineLearningCSV.zip` (~224MB compressed). This is
   CICFlowMeter output: already aggregated into per-flow records with a `Label` column,
   no packet processing needed on your end.
3. **Important**: you need the variant that keeps `Source IP` / `Destination IP` /
   `Timestamp` columns — some redistributions (e.g. certain Kaggle mirrors) strip these
   for anonymization. `prepare_dataset.py` needs them to bucket flows into per-source
   time windows; it'll skip any CSV missing them and tell you why.
4. Extract the per-day CSVs into `data/raw/` (create it — gitignored, not committed):
   ```
   backend/ml_training/data/raw/
     Monday-WorkingHours.pcap_ISCX.csv
     Tuesday-WorkingHours.pcap_ISCX.csv
     Wednesday-workingHours.pcap_ISCX.csv
     Thursday-*.csv
     Friday-*.csv           <- has the PortScan and DDoS labels
   ```

## Running the pipeline

```bash
cd backend/ml_training
pip install -r requirements.txt
python prepare_dataset.py --raw-dir data/raw --out data/processed/windows.csv
python train_model.py --data data/processed/windows.csv --out ../app/ml/anomaly_model_v1.joblib
```

`prepare_dataset.py` groups flows by `(source IP, 120-second window)` — matching
`config.ML_WINDOW_SECONDS` — and computes the same 7 features `detection.py` computes
live, labeling each window `benign` / `portscan` / `dos` by the flows inside it.

`train_model.py` trains a `RandomForestClassifier`, holding out the Friday CSV (or
whichever `--test-days` you pass) rather than a random split, since flows within one
day/attack run are highly correlated — a random split would leak test-set patterns into
training and overstate accuracy. It reports the metric that actually matters here: the
false-positive rate specifically on benign windows shaped like heavy multi-tab browsing
(high connection count, high `established_ratio`, high `common_web_port_ratio`). If
that number isn't low, don't ship the artifact — that's the exact bug this exists to fix.

## What happens after that

`ml_detection.py` looks for `../app/ml/anomaly_model_v1.joblib` at import time. If it's
not there (the default, until you run this pipeline), behavior is unchanged from today
— pure self-calibrating `IsolationForest`, nothing here affects it. Once the artifact
exists, it's used as an *additional* independent signal (see `ml_detection.py`'s
`_load_supervised`/`_score_supervised`): a confident supervised prediction of `portscan`
or `dos` fires the ML rule even if the session's own `IsolationForest` baseline has
absorbed that pattern as "normal" (a known limitation of the pure self-calibrating
approach — a long-running attack scenario eventually teaches it that shape is fine).
The two detectors are complementary, not either/or: supervised catches known attack
shapes from real-world data; unsupervised catches whatever's unusual for *this*
session that the training set never saw.

## Retraining

Re-run both scripts whenever you want to retrain (new data, tuned hyperparameters,
different `--test-days`). The artifact carries its own `trained_at`/`version` metadata
(see the dict `train_model.py` dumps) — bump `version` in `train_model.py` if you
change the feature set, so an old artifact from before a feature was added doesn't get
silently loaded against a mismatched live feature vector.
