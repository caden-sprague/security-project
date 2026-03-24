# IoT Healthcare Intrusion Prevention System

**Group Members:** Aleena Tomy, Caden Sprague, Devin Schupbach, Widyane Kasbi

Based on: *A Framework for Malicious Traffic Detection in IoT Healthcare Environment*

## Overview

This project replicates and extends the paper's machine learning-based malicious traffic detection framework for IoT healthcare environments. The paper uses IoT-specific datasets and ML classifiers to detect malicious MQTT traffic — our contribution transforms that passive detection system into an active **Intrusion Prevention System (IPS)**.

When malicious traffic is detected, the system automatically:
- Inserts blocking rules via `iptables` to reject the attacker's IP
- Terminates the malicious connection
- Logs all enforcement actions for analysis

A **debug mode** is also included for safe demonstration, prompting for user confirmation before any firewall rules are applied.

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
| `CreateRF.py` | Trains the Random Forest classifier (based on the paper's code) |
| `requirements.txt` | Python dependencies |
| `rf_model.pkl` | Saved trained model *(not committed — generate locally, see below)* |

## Setup

```bash
pip3 install -r requirements.txt
```

## Usage

### Train / Evaluate the Model

```bash
python3 CreateRF.py
```

Trains the Random Forest on the ICU dataset and evaluates it on the held-out test set, printing accuracy, precision, recall, F1-score, and the confusion matrix. The trained model is saved to `rf_model.pkl` — subsequent runs skip retraining and load from disk automatically.

## Model Details

- Algorithm: Random Forest Classifier
- Max depth: 10
- Train/test split: 70% / 30% (`random_state=100`)
- Fixed random seed ensures fully reproducible results
