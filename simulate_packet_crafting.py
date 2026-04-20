"""
MQTT Packet Crafting Attack Simulator
Attacker: Devin Schupbach

The MQTT Packet Crafting attack sends specially crafted, malformed MQTT packets
designed to crash or destabilise the MQTT broker. The attacker establishes a
TCP connection, then publishes messages *before* sending a valid CONNECT
request, violating the MQTT protocol state machine. The broker rejects these
with TCP RST (reset) frames. In large volumes, this can cause denial-of-service
or expose memory-corruption vulnerabilities in the broker.

Data source:
    Real packets from ICUDatasetProcessed/Attack.csv, filtered to rows where:
        tcp.flags.reset == 1
    This yields 1,633 rows — actual TCP RST packets captured by IoT-Flock
    when the broker rejected the attacker's malformed packets. This filter
    is highly reliable: in the entire normal traffic dataset (108,568 rows of
    patient and environmental monitoring), tcp.flags.reset is 0 on every
    single packet. A reset flag appearing in ICU traffic is an unambiguous
    sign of malicious activity.

Usage:
    python simulate_packet_crafting.py
    python simulate_packet_crafting.py --windows 10 --window-size 30
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
ATTACKER_IP = "192.168.1.103"   # simulated malicious device

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
    Return n real MQTT Packet Crafting rows from the held-out test set.

    Source: X_test rows (never seen during training) where:
        tcp.flags.reset == 1
    The test set contains ~472 packet crafting rows. Using X_test guarantees
    no overlap with the training data. tcp.flags.reset is 0 on every single
    row of normal ICU traffic, making this the strongest single-feature
    attack indicator in the dataset.
    """
    attack_test = X_test[y_test == 1].reset_index(drop=True)
    craft = attack_test[attack_test["tcp.flags.reset"] == 1]
    return craft.sample(n=n, replace=len(craft) < n, random_state=13).reset_index(drop=True)


# ── demo runner ──────────────────────────────────────────────────────────────

def run(model=None, encoder=None, X_test=None, y_test=None,
        standalone=True, n_windows=None, window_size=None):
    """
    Classify rolling windows of held-out packet crafting traffic and trigger IPS.

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
        print(f"  {BOLD}MQTT Packet Crafting — Attack Simulation{RESET}")
        print(f"  Attacker : Devin Schupbach  |  Simulated IP: {ATTACKER_IP}")
        print("=" * 70)
        print(f"  {n_windows * window_size} crafted packets  "
              f"({n_windows} windows × {window_size} packets/window)")
        print(f"  Each packet: DUP PUBLISH before CONNECT, ~40% trigger TCP RST")
        print()

    logging.info("=== Packet Crafting simulation start — %d windows ===", n_windows)

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
            "CRAFT W%02d  verdict=%s  attack_pkts=%d/%d  prob=%.1f%%  correct=%s",
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

    logging.info("=== Packet Crafting simulation end ===")
    return {
        "attack_name":     "MQTT Packet Crafting",
        "windows_correct": tally["correct"],
        "windows_total":   tally["total"],
        "n_blocked":       len(blocked),
    }


if __name__ == "__main__":
    run(standalone=True)
