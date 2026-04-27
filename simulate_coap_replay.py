"""
MQTT Distributed Denial-of-Service Simulator (TCP SYN Flood)
Attacker: Widyane Kasbi

The MQTT DDoS attack is a TCP SYN Flood targeting the MQTT broker on port 1883.
The attacker (192.168.1.90 in the dataset) sends a rapid stream of TCP SYN
connection-request packets to the broker without ever completing the three-way
handshake. Each half-open connection consumes a slot in the broker's connection
table. Under sufficient volume, the broker cannot accept new connections from
legitimate ICU devices.

This matches the "MQTT distributed denial-of-service" attack named in the
paper's Section 3.2.2 introduction paragraph (Faour et al., Sensors 2021).

Note on dataset:
    The paper also describes a CoAP Replay attack. However, after inspecting
    the full Attack.csv (80,126 rows), every row has ip.proto == 6 (TCP).
    There are zero UDP packets in the dataset. CoAP runs over UDP (ip.proto 17),
    so CoAP Replay traffic does not exist in the captured data. The SYN flood
    rows represent the DDoS component of the attack traffic.

Data source:
    Rows from the held-out test split (X_test, 30% of the dataset, never seen
    during training), filtered to attack rows where:
        mqtt.msgtype == 0  AND  tcp.flags.ack == 0  AND  tcp.flags.reset == 0
    ~549 matching rows exist in the test split. These are TCP SYN packets with
    no MQTT payload (msgtype 0), no ACK flag (handshake never completed), and
    no RST flag (distinguishing them from packet-crafting resets). This pattern
    is absent from all 108,568 normal traffic rows.

    Note: tcp.flags.syn is not among the 10 model features, so the filter uses
    the three available flags above as a proxy. In the full Attack.csv (where
    tcp.flags.syn is present), applying tcp.flags.syn==1 AND tcp.flags.ack==0
    yields 1,941 rows, all confirmed from the attacker subnet (192.168.1.90)
    or the ICU device at 10.16.120.44.

Usage:
    python simulate_coap_replay.py
    python simulate_coap_replay.py --windows 10 --window-size 30
"""

import os
import sys
import time
import logging
import subprocess
from datetime import datetime

import pandas as pd
import joblib

# ── config ──────────────────────────────────────────────────────────────────

MODEL_PATH  = "rf_model.pkl"
LOG_PATH    = "ips_demo.log"
ATTACKER_IP = "192.168.1.104"   # simulated malicious device

FEATURES = [
    "frame.time_delta", "tcp.time_delta",
    "tcp.flags.ack", "tcp.flags.push", "tcp.flags.reset",
    "mqtt.hdrflags", "mqtt.msgtype", "mqtt.qos", "mqtt.retain", "mqtt.ver",
]

GREEN = "\033[92m"
RED   = "\033[91m"
BOLD  = "\033[1m"
RESET = "\033[0m"

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    filemode="a",
)


# ── helpers ──────────────────────────────────────────────────────────────────

def _parse_int_arg(flag, default):
    try:
        return int(sys.argv[sys.argv.index(flag) + 1])
    except (ValueError, IndexError):
        return default


def _block_ip(ip, blocked):
    """Insert a DROP rule via iptables. On Windows/non-root, logs the intent."""
    if ip in blocked:
        return
    blocked.add(ip)
    try:
        result = subprocess.run(
            ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            print(f"  {RED}{BOLD}[BLOCKED]{RESET}  iptables -I INPUT -s {ip} -j DROP")
            logging.warning("BLOCKED  iptables -I INPUT -s %s -j DROP", ip)
            return
    except FileNotFoundError:
        pass  # iptables not installed (Windows)
    print(f"  {RED}{BOLD}[IPS]{RESET}  Would block: iptables -I INPUT -s {ip} -j DROP")
    logging.warning("IPS (simulated)  block %s", ip)


def _unblock_all(blocked):
    for ip in list(blocked):
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True,
            )
        except FileNotFoundError:
            pass


# ── traffic loader ───────────────────────────────────────────────────────────

def generate(n, encoder, X_test, y_test):
    """
    Return n real MQTT DDoS (TCP SYN Flood) rows from the held-out test set.

    Source: X_test rows (never seen during training) where:
        mqtt.msgtype == 0  AND  tcp.flags.ack == 0  AND  tcp.flags.reset == 0
    The test set contains ~549 matching rows. These are TCP SYN packets with
    no MQTT payload, no ACK (handshake never completed), and no RST flag.
    tcp.flags.syn is not among the 10 model features so this three-flag
    combination is the closest available proxy within the feature set.
    Zero overlap with the other three attack filters. Zero false positives
    on the 108,568 normal traffic rows.
    """
    attack_test = X_test[y_test == 1].reset_index(drop=True)
    ddos = attack_test[
        (attack_test["mqtt.msgtype"] == 0) &
        (attack_test["tcp.flags.ack"] == 0) &
        (attack_test["tcp.flags.reset"] == 0)
    ]
    return ddos.sample(n=n, replace=len(ddos) < n, random_state=99).reset_index(drop=True)


# ── demo runner ──────────────────────────────────────────────────────────────

def run(model=None, encoder=None, X_test=None, y_test=None,
        standalone=True, n_windows=None, window_size=None):
    """
    Classify rolling windows of held-out MQTT DDoS (TCP SYN flood) traffic and trigger IPS.

    Returns:
        dict with attack_name, windows_correct, windows_total, n_blocked
    """
    n_windows   = n_windows   or _parse_int_arg("--windows", 5)
    window_size = window_size or _parse_int_arg("--window-size", 20)

    if model is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"Model not found at '{MODEL_PATH}'. Run CreateRF.py first."
            )
        saved   = joblib.load(MODEL_PATH)
        model   = saved["model"]
        encoder = saved["hdrflags_encoder"]
        X_test  = saved["X_test"]
        y_test  = saved["y_test"]

    attack_col = list(model.classes_).index(1)
    blocked    = set()

    traffic = generate(n_windows * window_size, encoder, X_test, y_test)

    if standalone:
        print()
        print("=" * 70)
        print(f"  {BOLD}MQTT DDoS (TCP SYN Flood) -- Attack Simulation{RESET}")
        print(f"  Attacker : Widyane Kasbi  |  Simulated IP: {ATTACKER_IP}")
        print("=" * 70)
        print(f"  {n_windows * window_size} TCP SYN packets  "
              f"({n_windows} windows x {window_size} packets/window)")
        print(f"  Each packet: SYN to port 1883, no MQTT payload, handshake never completed")
        print()

    logging.info("=== MQTT DDoS (TCP SYN Flood) simulation start -- %d windows ===", n_windows)

    tally = {"correct": 0, "total": 0}

    for i in range(n_windows):
        window     = traffic.iloc[i * window_size:(i + 1) * window_size]
        preds      = model.predict(window)
        probs      = model.predict_proba(window)
        attack_pct = preds.mean() * 100
        mean_prob  = probs[:, attack_col].mean() * 100
        verdict    = "ATTACK" if attack_pct >= 50 else "NORMAL"
        correct    = verdict == "ATTACK"

        tally["total"] += 1
        if correct:
            tally["correct"] += 1

        colour  = RED if verdict == "ATTACK" else GREEN
        outcome = f"{GREEN}CORRECT{RESET}" if correct else f"{RED}WRONG{RESET}"
        ts      = datetime.now().strftime("%H:%M:%S")

        print(f"[{ts}] Window {i+1:>2}  |  "
              f"True: ATTACK  "
              f"Verdict: {colour}{BOLD}{verdict}{RESET}  "
              f"Attack pkts: {int(preds.sum()):>2}/{window_size}  "
              f"Avg prob: {mean_prob:5.1f}%  "
              f"{outcome}")

        logging.info(
            "DDOS W%02d  verdict=%s  attack_pkts=%d/%d  prob=%.1f%%  correct=%s",
            i + 1, verdict, int(preds.sum()), window_size, mean_prob, correct,
        )

        if verdict == "ATTACK":
            _block_ip(ATTACKER_IP, blocked)

        time.sleep(0.4)

    if standalone:
        print()
        print(f"  Windows correct : {tally['correct']}/{tally['total']}")
        print(f"  IPs blocked     : {len(blocked)}")
        print("=" * 70)
        _unblock_all(blocked)

    logging.info("=== MQTT DDoS (TCP SYN Flood) simulation end ===")
    return {
        "attack_name":     "MQTT DDoS (TCP SYN Flood)",
        "windows_correct": tally["correct"],
        "windows_total":   tally["total"],
        "n_blocked":       len(blocked),
    }


if __name__ == "__main__":
    run(standalone=True)
