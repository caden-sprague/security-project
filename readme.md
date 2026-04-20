# IoT Healthcare Intrusion Prevention System

**Group Members:** Aleena Tomy, Caden Sprague, Devin Schupbach, Widyane Kasbi

Based on: *A Framework for Malicious Traffic Detection in IoT Healthcare Environment*
Hady Salim Faour et al., Sensors 2021, 21(9), 3025. https://doi.org/10.3390/s21093025

---

## Overview

This project replicates and extends the paper's machine learning-based malicious
traffic detection framework for IoT healthcare environments. The paper uses
IoT-specific datasets and ML classifiers to detect malicious MQTT/CoAP traffic.
Our contribution transforms that passive detection system into an active
**Intrusion Prevention System (IPS)** with per-attack simulators.

**Our extension** — each team member takes one of the four attack types from
the paper and isolates its rows from the held-out test split (`X_test`) using
a network-signature filter. Using `X_test` guarantees the model has never seen
these rows during training. The rows are fed into the shared Random Forest
classifier in rolling windows. When an attack window is detected, the system
automatically inserts a DROP rule via `iptables` for the attacker's IP.

| Team Member | Attack | Filter on held-out test set | Test-set rows |
|-------------|--------|-----------------------------|---------------|
| Aleena Tomy | MQTT Publish Flood | `mqtt.msgtype==3` AND `frame.time_delta<0.005` | 7,693 |
| Caden Sprague | MQTT Auth Bypass | `mqtt.msgtype==1` AND `mqtt.ver==4` | 557 |
| Devin Schupbach | MQTT Packet Crafting | `tcp.flags.reset==1` | 472 |
| Widyane Kasbi | CoAP Replay | `mqtt.msgtype==0` AND `tcp.flags.ack==0` | 1,007 |


---

## Dataset

The `ICUDatasetProcessed/` directory contains three CSV files generated with
IoT-Flock to simulate a two-bed ICU network (patient monitoring + environmental
sensors + an attacker network of 10 malicious devices):

| File | Size | Description |
|------|------|-------------|
| `Attack.csv` | 74 MB | 80,126 malicious traffic samples (all 4 attack types) |
| `environmentMonitoring.csv` | 8.6 MB | Normal environmental sensor traffic |
| `patientMonitoring.csv` | 21 MB | Normal patient monitoring traffic |

The classifier uses the 10 features selected by the paper via logistic-regression
feature importance: `frame.time_delta`, `tcp.time_delta`, `tcp.flags.ack`,
`tcp.flags.push`, `tcp.flags.reset`, `mqtt.hdrflags`, `mqtt.msgtype`,
`mqtt.qos`, `mqtt.retain`, `mqtt.ver`.

The dataset is pre-included in the repository so results can be reproduced
without any external download.

**On false positives:** The model achieves a false positive rate of 0.15 %
on the held-out test set: only 49 out of 32,620 normal packets were
incorrectly flagged as attacks (visible in the confusion matrix printed by
`CreateRF.py`). In a healthcare deployment this matters — a false positive
blocks a legitimate medical device, which is as dangerous as a missed attack.

Two design decisions keep false positives low:

1. **Rolling-window voting** — the IPS classifies 20-packet windows, not
   individual packets. A window is only flagged as an attack if ≥ 50 % of its
   packets are classified malicious. A single anomalous packet never triggers
   a block on its own.
2. **High-precision model** — Random Forest achieves 99.71 % precision on this
   dataset, meaning fewer than 1 in 300 block decisions is a false alarm. The
   feature set (MQTT application-layer + TCP timing) gives the model a strong
   signal that distinguishes attack traffic from legitimate sensor readings.

---

## Files

| File | Description |
|------|-------------|
| `CreateRF.py` | Trains the Random Forest, evaluates it, saves `rf_model.pkl` |
| `demo_csv.py` | Original IPS demo — rolling windows from the test split, blocks IPs via iptables |
| `simulate_flood.py` | MQTT Publish Flood simulator (Aleena) |
| `simulate_auth_bypass.py` | MQTT Auth Bypass simulator (Caden) |
| `simulate_packet_crafting.py` | MQTT Packet Crafting simulator (Devin) |
| `simulate_coap_replay.py` | CoAP Replay simulator (Widyane) |
| `run_all_attacks.py` | Unified demo: normal baseline → all 4 attacks in sequence |
| `models/svm_model.py` | SVM comparison model (stratified 20 % sample + StandardScaler) |
| `requirements.txt` | Python dependencies |
| `rf_model.pkl` | Saved trained model *(not committed — generate locally, see below)* |

---

## Setup

**Requirements:** Python 3.8+, pip

```bash
git clone https://github.com/ThingzDefense/Malicious-Traffic-Detection-in-IoT-Healthcare-Environment
cd Malicious-Traffic-Detection-in-IoT-Healthcare-Environment
pip install -r requirements.txt
```

> **Note on sklearn version:** If you see `InconsistentVersionWarning` when
> loading `rf_model.pkl`, delete it and re-run `python CreateRF.py` to rebuild
> the model with your installed sklearn version.

`iptables` is only needed for real firewall enforcement (Linux + root).
On Windows/macOS the IPS demo works fine — it prints the intended iptables
command instead of executing it.

---

## Usage

### Step 1 — Train the model

```bash
python CreateRF.py
```

Trains a Random Forest (max_depth=10, 70/30 split, random_state=100) on the
combined ICU dataset and prints accuracy, precision, recall, F1-score, and
confusion matrix. Saves the model to `rf_model.pkl`.

Expected results (matching the paper):
- Accuracy  ≈ 99.51 %
- Precision ≈ 99.71 %
- Recall    ≈ 99.80 %
- F1 Score  ≈ 99.65 %

### Step 2 — Run the unified 4-attack demo (recommended)

```bash
python run_all_attacks.py
```

Runs five phases in sequence:

1. **Normal traffic baseline** — held-out test set, no blocks expected
2. **MQTT Publish Flood** (Aleena) — rapid PUBLISH flood, IP 192.168.1.101 blocked
3. **MQTT Auth Bypass** (Caden) — CONNECT with no password, IP 192.168.1.102 blocked
4. **MQTT Packet Crafting** (Devin) — malformed packets + RST, IP 192.168.1.103 blocked
5. **CoAP Replay** (Widyane) — UDP/CoAP replayed packets, IP 192.168.1.104 blocked

Optional flags:
```bash
python run_all_attacks.py --windows 3 --window-size 20
```

### Step 3 — Run individual attack simulators

```bash
python simulate_flood.py
python simulate_auth_bypass.py
python simulate_packet_crafting.py
python simulate_coap_replay.py
```

Each accepts `--windows N` and `--window-size N` flags.

### Original mixed-test demo

```bash
python demo_csv.py [--debug]
```

Uses the raw held-out test split (normal + attack rows mixed). `--debug` prompts
for confirmation before each iptables change.

### SVM comparison model

```bash
python models/svm_model.py
```

Trains an SVM on a stratified 20 % sample with StandardScaler and compares
performance against the Random Forest.

---

## What Works

- Training the Random Forest and reproducing the paper's reported metrics
- Rolling-window IPS classification on the held-out test set (`demo_csv.py`)
- All four per-attack simulators, standalone and via `run_all_attacks.py`
- iptables DROP rule insertion and cleanup on Linux with root (`sudo`)
- Graceful fallback on Windows/macOS — prints the intended iptables command
- SVM comparison model with proper feature scaling and model serialisation
- Full logging of every detection and IPS action to `ips_demo.log`
- Debug mode (`--debug`) for manual confirmation before each firewall rule

## What Does Not Work

- **Live packet capture** — there is no real-time pcap → feature pipeline; all
  classification uses pre-recorded dataset rows from the held-out test split
- **iptables on Windows/macOS** — actual DROP rules require Linux + root; on
  Windows the IPS prints the intended command instead of executing it
- **TCP connection termination** — the IPS inserts a DROP rule that silently
  discards future packets from the attacker's IP, but does not actively
  terminate the existing TCP connection. A full implementation would also send
  a TCP RST to the attacker (`iptables -I OUTPUT -d <ip> -j REJECT
  --reject-with tcp-reset`). This is left as future work.
- **Per-attack-type labels in the dataset** — `Attack.csv` has no column
  identifying which attack type each row belongs to; all 80,126 rows carry the
  same `class=Attack` label. The four simulators separate attack types by
  applying network-signature filters (e.g. `tcp.flags.reset==1` for Packet
  Crafting), but the model itself still does binary classification only
  (normal vs. attack) — it does not identify the specific attack type
- **SVM on full dataset** — training would exceed an hour; the script uses a
  20 % stratified sample

---

## Model Details

| Parameter | Value |
|-----------|-------|
| Algorithm | Random Forest |
| Max depth | 10 |
| Train/test split | 70 % / 30 % |
| Random state | 100 (fully reproducible) |
| Features | 10 (paper-selected via logistic regression importance) |

Top 3 features by RF importance: `frame.time_delta`, `tcp.time_delta`, `mqtt.msgtype`
