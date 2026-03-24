"""
IoT MQTT Traffic Detector
Usage: python3 detect.py <path_to_pcap>

Takes a pcap, extracts the 10 features the RF model was trained on,
and prints a prediction (attack / normal) with confidence.
"""

import sys
import os
import subprocess
import tempfile

import pandas as pd
import joblib

MODEL_PATH = "rf_model.pkl"

FEATURES = [
    "frame.time_delta",
    "tcp.time_delta",
    "tcp.flags.ack",
    "tcp.flags.push",
    "tcp.flags.reset",
    "mqtt.hdrflags",
    "mqtt.msgtype",
    "mqtt.qos",
    "mqtt.retain",
    "mqtt.ver",
]

TSHARK_FIELDS = " ".join(f"-e {f}" for f in FEATURES)
TSHARK_OPTS   = "-E header=y -E separator=, -E quote=d -E occurrence=f"


def extract_features(pcap_path: str, encoder=None) -> pd.DataFrame:
    """Run tshark on pcap and return a DataFrame with the 10 model features."""
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
        tmp_path = tmp.name

    cmd = (
        f"tshark -r {pcap_path} -T fields "
        f"{TSHARK_FIELDS} {TSHARK_OPTS} > {tmp_path}"
    )

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"tshark failed:\n{result.stderr}")

    df = pd.read_csv(tmp_path, low_memory=False)
    os.unlink(tmp_path)
    return preprocess(df, encoder)


def preprocess(df: pd.DataFrame, encoder=None) -> pd.DataFrame:
    """Align DataFrame to the 10 expected features, matching training preprocessing."""
    for col in FEATURES:
        if col not in df.columns:
            df[col] = 0

    df = df[FEATURES].copy()
    df.fillna(0, inplace=True)

    # mqtt.hdrflags: use the saved LabelEncoder for exact parity with training.
    # For unseen values, fall back to 0.
    if encoder is not None:
        known = set(encoder.classes_)
        df["mqtt.hdrflags"] = df["mqtt.hdrflags"].apply(
            lambda v: encoder.transform([v])[0] if v in known else 0
        )
    else:
        # Fallback if model was saved before encoder was included
        df["mqtt.hdrflags"] = df["mqtt.hdrflags"].apply(
            lambda v: int(str(v), 16) if str(v).startswith("0x") else 0
        )

    df = df.infer_objects()
    return df


def predict(pcap_path: str):
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model not found at '{MODEL_PATH}'. Run CreateRF.py first.")

    saved = joblib.load(MODEL_PATH)
    model   = saved["model"]
    encoder = saved.get("hdrflags_encoder")

    print(f"[*] Extracting features from: {pcap_path}")
    df = extract_features(pcap_path, encoder)
    print(f"[*] Packets captured: {len(df)}")

    # Drop rows that are entirely zero (non-TCP/MQTT packets with no useful fields)
    mqtt_cols = ["mqtt.hdrflags", "mqtt.msgtype", "mqtt.qos", "mqtt.retain", "mqtt.ver"]
    df_mqtt = df[df[mqtt_cols].any(axis=1)]

    if df_mqtt.empty:
        print("[!] No MQTT packets found in capture — cannot classify.")
        return

    print(f"[*] MQTT packets to classify: {len(df_mqtt)}")

    probs      = model.predict_proba(df_mqtt)          # shape: (n_packets, 2)
    preds      = model.predict(df_mqtt)                # 0=normal, 1=attack

    # model.classes_ is [0, 1], so column 1 is P(attack)
    attack_col = list(model.classes_).index(1)
    attack_pct = preds.mean() * 100
    mean_attack_prob = probs[:, attack_col].mean() * 100

    label = "ATTACK" if attack_pct >= 50 else "NORMAL"

    print()
    print("=" * 40)
    print(f"  Verdict       : {label}")
    print(f"  Attack pkts   : {preds.sum()} / {len(preds)}  ({attack_pct:.1f}%)")
    print(f"  Avg attack prob: {mean_attack_prob:.1f}%")
    print("=" * 40)

    return label, attack_pct, mean_attack_prob


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 detect.py <path_to_pcap>")
        sys.exit(1)

    pcap = sys.argv[1]
    if not os.path.exists(pcap):
        print(f"Error: file not found — {pcap}")
        sys.exit(1)

    predict(pcap)
