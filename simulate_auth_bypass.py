"""
MQTT Authentication Bypass Attack Simulator
Attacker: Caden Sprague

The MQTT Authentication Bypass exploits a vulnerability in older MQTT broker
configurations where a CONNECT packet that omits the password field (while
supplying a valid username) is still accepted. The attacker sends a stream of
unauthenticated CONNECT requests, gaining unauthorised broker access and
potentially injecting or reading medical sensor data.

Attack signature (10-feature profile):
  - frame.time_delta  : 0.001–0.1 s (new TCP+MQTT handshake per attempt)
  - tcp.time_delta    : 0.001–0.5 s  (SYN-ACK roundtrip latency)
  - tcp.flags.ack     : alternates 0/1 (0 = SYN, 1 = established)
  - tcp.flags.push    : alternates 0/1 (0 = TCP setup, 1 = CONNECT payload)
  - tcp.flags.reset   : 0 (broker accepts or ignores, does not reset)
  - mqtt.hdrflags=1   : CONNECT fixed header (0x10 encoded)
  - mqtt.msgtype=1    : CONNECT control packet type
  - mqtt.qos=0        : CONNECT packets always QoS 0
  - mqtt.retain=0     : no retain flag on CONNECT
  - mqtt.ver=4        : MQTT 3.1.1 (protocol level 4) — used by attacker

Usage:
    python simulate_auth_bypass.py
    python simulate_auth_bypass.py --windows 10 --window-size 30
"""

import os
import sys
import time
import logging
import subprocess
from datetime import datetime

import numpy as np
import pandas as pd
import joblib

# ── config ──────────────────────────────────────────────────────────────────

MODEL_PATH  = "rf_model.pkl"
LOG_PATH    = "ips_demo.log"
ATTACKER_IP = "192.168.1.102"   # simulated malicious device

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


# ── traffic generator ────────────────────────────────────────────────────────

def generate(n, encoder):
    """
    Return a DataFrame of n synthetic MQTT Auth Bypass CONNECT packets.

    Each attempt follows the pattern:
      1. TCP SYN (ack=0, push=0)
      2. TCP SYN-ACK / ACK (ack=1, push=0)
      3. MQTT CONNECT with no password (ack=1, push=1, msgtype=1, ver=4)

    We model the steady-state CONNECT flood: mostly ack=1, push=1.
    A fraction (~30 %) are pure TCP setup frames (ack=0, push=0) to reflect
    the repeated connection teardown-and-retry pattern.
    """
    rng = np.random.default_rng(7)

    classes     = list(encoder.classes_)
    connect_hdr = classes.index("0x00000010") if "0x00000010" in classes else 0

    # 70 % of frames carry the MQTT CONNECT payload; 30 % are TCP setup
    is_payload = rng.random(n) > 0.30

    return pd.DataFrame({
        # Slower than flood — each attempt needs a full TCP handshake
        "frame.time_delta": rng.uniform(0.001, 0.1, n),
        "tcp.time_delta":   rng.uniform(0.001, 0.5, n),
        # TCP setup frames have ack=0; payload frames have ack=1
        "tcp.flags.ack":    is_payload.astype(int),
        "tcp.flags.push":   is_payload.astype(int),
        # Broker does not reset — it either accepts or ignores the bypass attempt
        "tcp.flags.reset":  np.zeros(n, dtype=int),
        # CONNECT fixed header (encoded)
        "mqtt.hdrflags":    np.where(is_payload, connect_hdr, 0).astype(int),
        # msgtype=1 (CONNECT) only on payload frames; 0 on pure TCP frames
        "mqtt.msgtype":     np.where(is_payload, 1, 0).astype(int),
        "mqtt.qos":         np.zeros(n, dtype=int),
        "mqtt.retain":      np.zeros(n, dtype=int),
        # MQTT 3.1.1 protocol level = 4; 0 on non-CONNECT frames
        "mqtt.ver":         np.where(is_payload, 4, 0).astype(int),
    })


# ── demo runner ──────────────────────────────────────────────────────────────

def run(model=None, encoder=None, standalone=True,
        n_windows=None, window_size=None):
    """
    Classify rolling windows of simulated auth bypass traffic and trigger IPS.

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

    attack_col = list(model.classes_).index(1)
    blocked    = set()

    traffic = generate(n_windows * window_size, encoder)

    if standalone:
        print()
        print("=" * 70)
        print(f"  {BOLD}MQTT Authentication Bypass — Attack Simulation{RESET}")
        print(f"  Attacker : Caden Sprague  |  Simulated IP: {ATTACKER_IP}")
        print("=" * 70)
        print(f"  {n_windows * window_size} CONNECT packets  "
              f"({n_windows} windows × {window_size} packets/window)")
        print(f"  Each packet: CONNECT, mqtt.ver=4 (MQTT 3.1.1), no password")
        print()

    logging.info("=== Auth Bypass simulation start — %d windows ===", n_windows)

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
            "AUTH W%02d  verdict=%s  attack_pkts=%d/%d  prob=%.1f%%  correct=%s",
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

    logging.info("=== Auth Bypass simulation end ===")
    return {
        "attack_name":     "MQTT Auth Bypass",
        "windows_correct": tally["correct"],
        "windows_total":   tally["total"],
        "n_blocked":       len(blocked),
    }


if __name__ == "__main__":
    run(standalone=True)
