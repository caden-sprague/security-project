"""
CoAP Replay Attack Simulator
Attacker: Widyane Kasbi

The CoAP Replay attack targets CoAP (Constrained Application Protocol), the
UDP-based IoT protocol used by environmental sensors in the ICU (CO sensor,
fire sensor, smoke detector, etc.). The attacker scans the network to intercept
legitimate CoAP messages, then replays them — or injects modified payloads with
spoofed source IPs — to the CoAP server. In a healthcare context, this could
cause the environmental control unit to act on stale or falsified sensor data
(e.g., wrong CO or temperature readings).

This attack is particularly dangerous because CoAP is stateless and UDP-based,
making it harder to detect with traditional TCP-based intrusion detection.

Data source:
    Rows from the held-out test split (X_test, 30% of the dataset, never seen
    during training), filtered to attack rows where:
        mqtt.msgtype == 0  AND  tcp.flags.ack == 0
    ~1,007 matching rows exist in the test split. Because CoAP runs over UDP
    (not TCP), the tshark capture fills all tcp.* and mqtt.* fields with 0.
    This all-zero pattern never appears in normal MQTT ICU traffic, where
    tcp.flags.ack is 1 on every single packet.

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
    Return n real CoAP Replay rows from the held-out test set.

    Source: X_test rows (never seen during training) where:
        mqtt.msgtype == 0  AND  tcp.flags.ack == 0
    The test set contains ~1,007 CoAP replay rows. Using X_test guarantees
    no overlap with the training data. Because CoAP uses UDP (not TCP), the
    tshark capture fills all tcp.* and mqtt.* fields with 0 — a pattern that
    never appears in normal MQTT ICU traffic where tcp.flags.ack is always 1.
    """
    attack_test = X_test[y_test == 1].reset_index(drop=True)
    coap = attack_test[
        (attack_test["mqtt.msgtype"] == 0) &
        (attack_test["tcp.flags.ack"] == 0)
    ]
    return coap.sample(n=n, replace=len(coap) < n, random_state=99).reset_index(drop=True)


# ── demo runner ──────────────────────────────────────────────────────────────

def run(model=None, encoder=None, X_test=None, y_test=None,
        standalone=True, n_windows=None, window_size=None):
    """
    Classify rolling windows of held-out CoAP replay traffic and trigger IPS.

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
        print(f"  {BOLD}CoAP Replay — Attack Simulation{RESET}")
        print(f"  Attacker : Widyane Kasbi  |  Simulated IP: {ATTACKER_IP}")
        print("=" * 70)
        print(f"  {n_windows * window_size} CoAP UDP packets  "
              f"({n_windows} windows × {window_size} packets/window)")
        print(f"  Each packet: UDP/CoAP, all MQTT/TCP fields = 0")
        print()

    logging.info("=== CoAP Replay simulation start — %d windows ===", n_windows)

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
            "COAP W%02d  verdict=%s  attack_pkts=%d/%d  prob=%.1f%%  correct=%s",
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

    logging.info("=== CoAP Replay simulation end ===")
    return {
        "attack_name":     "CoAP Replay",
        "windows_correct": tally["correct"],
        "windows_total":   tally["total"],
        "n_blocked":       len(blocked),
    }


if __name__ == "__main__":
    run(standalone=True)
