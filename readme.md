# IoT Healthcare Intrusion Prevention System

**Group Members:** Aleena Tomy, Caden Sprague, Devin Schupbach, Widyane Kasbi

Based on: *A Framework for Malicious Traffic Detection in IoT Healthcare Environment*

## Overview

This project replicates and extends the paper's machine learning-based malicious traffic detection framework for IoT healthcare environments. The paper uses IoT-specific datasets and ML classifiers to detect malicious MQTT traffic — our contribution transforms that passive detection system into an active **Intrusion Prevention System (IPS)**.

When malicious traffic is detected, the system automatically:
- Inserts blocking rules via `iptables` to reject the attacker's IP
- Logs all enforcement actions and detection results to `ips_demo.log`

## Dataset

The `ICUDatasetProcessed/` directory contains three CSV files provided by the paper, representing simulated ICU network traffic:

| File | Description |
|------|-------------|
| `Attack.csv` | Malicious/attack traffic samples |
| `environmentMonitoring.csv` | Normal environment monitoring traffic |
| `patientMonitoring.csv` | Normal patient monitoring traffic |

The classifier uses 10 features selected in the paper: `frame.time_delta`, `tcp.time_delta`, `tcp.flags.ack`, `tcp.flags.push`, `tcp.flags.reset`, `mqtt.hdrflags`, `mqtt.msgtype`, `mqtt.qos`, `mqtt.retain`, and `mqtt.ver`.

## Files

| File | Description |
|------|-------------|
| `CreateRF.py` | Trains the Random Forest classifier and saves it to `rf_model.pkl` |
| `detect.py` | Extracts features from a pcap file and classifies traffic as NORMAL or ATTACK |
| `demo_csv.py` | IPS demo using the held-out test split — classifies rolling windows and blocks attacker IPs via iptables |
| `normal.py` | Simulates normal ICU sensor traffic via paho-mqtt |
| `malicious.py` | Simulates a flood attack via paho-mqtt |
| `requirements.txt` | Python dependencies |
| `rf_model.pkl` | Saved trained model *(not committed — generate locally, see below)* |

## Setup

```bash
pip3 install -r requirements.txt
```

tshark is also required for live capture (`detect.py`):

```bash
# Debian/Ubuntu
sudo apt-get install tshark
```

## Usage

### Train / Evaluate the Model

```bash
python3 CreateRF.py
```

Trains the Random Forest on the ICU dataset and evaluates it on the held-out test set, printing accuracy, precision, recall, F1-score, and the confusion matrix. The trained model is saved to `rf_model.pkl`.

### Run the IPS Demo

```bash
sudo python3 demo_csv.py [window_size] [n_windows]
```

Classifies rolling windows of packets from the held-out test split. Normal traffic windows are shown first, then attack windows. Each detected attack triggers an `iptables` DROP rule for a simulated attacker IP. All actions are logged to `ips_demo.log`. Requires `sudo` for iptables.

Defaults: 20 packets per window, 5 windows per class.

## Model Details

- Algorithm: Random Forest Classifier
- Max depth: 10
- Train/test split: 90% / 10% (`random_state=100`)
- Fixed random seed ensures fully reproducible results
