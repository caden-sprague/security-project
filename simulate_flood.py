"""
MQTT Publish Flood Attack Simulator
Attacker: Aleena Tomy

The MQTT Publish Flood is a DDoS attack at the application layer. The attacker
floods the MQTT broker with PUBLISH messages at an extremely high rate,
exhausting its resources and denying service to legitimate ICU medical devices.

Attack signature (10-feature profile):
  - frame.time_delta  : near zero (hundreds of packets per second)
  - tcp.time_delta    : near zero (TCP pipeline flooded)
  - tcp.flags.ack=1   : connection already established
  - tcp.flags.push=1  : data pushed immediately, no wait
  - tcp.flags.reset=0 : no resets — attacker stays connected
  - mqtt.hdrflags=3   : PUBLISH, QoS 0, no retain (0x30 encoded)
  - mqtt.msgtype=3    : PUBLISH control packet type
  - mqtt.qos=0        : fire-and-forget — no PUBACK needed (maximises rate)
  - mqtt.retain=0     : no retain flag
  - mqtt.ver=0        : device already connected; not a new CONNECT packet

Usage:
    python simulate_flood.py
    python simulate_flood.py --windows 10 --window-size 30
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

MODEL_PATH   = "rf_model.pkl"
LOG_PATH     = "ips_demo.log"
ATTACKER_IP  = "192.168.1.101"   # simulated malicious ICU device

FEATURES = [
    "frame.time_delta", "tcp.time_delta",
    "tcp.flags.ack", "tcp.flags.push", "tcp.flags.reset",
    "mqtt.hdrflags", "mqtt.msgtype", "mqtt.qos", "mqtt.retain", "mqtt.ver",
]

# ANSI colours
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
    """Read an integer CLI argument, e.g. --windows 10."""
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
    # iptables unavailable or failed — show what would happen
    print(f"  {RED}{BOLD}[IPS]{RESET}  Would block: iptables -I INPUT -s {ip} -j DROP")
    logging.warning("IPS (simulated)  block %s", ip)


def _unblock_all(blocked):
    """Remove every iptables rule this run created (cleanup)."""
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
    Return a DataFrame of n synthetic MQTT Publish Flood packets.

    The attacker publishes as fast as possible (QoS 0, fire-and-forget).
    frame.time_delta is orders of magnitude lower than normal ICU traffic
    (normal mean ≈ 0.13 s; flood mean ≈ 0.001 s).
    """
    rng = np.random.default_rng(42)

    # Look up the encoded integer for PUBLISH QoS=0 (hdrflags = '0x00000030')
    classes = list(encoder.classes_)
    publish_hdr = classes.index("0x00000030") if "0x00000030" in classes else 0

    return pd.DataFrame({
        # Flood rate: ~500–10 000 packets/sec → delta 0.0001–0.002 s
        "frame.time_delta": rng.uniform(0.0001, 0.002, n),
        "tcp.time_delta":   rng.uniform(0.0001, 0.001, n),
        # Established TCP connection: ACK=1, PSH=1, RST=0
        "tcp.flags.ack":    np.ones(n, dtype=int),
        "tcp.flags.push":   np.ones(n, dtype=int),
        "tcp.flags.reset":  np.zeros(n, dtype=int),
        # PUBLISH QoS=0 fixed header
        "mqtt.hdrflags":    np.full(n, publish_hdr, dtype=int),
        "mqtt.msgtype":     np.full(n, 3, dtype=int),   # 3 = PUBLISH
        "mqtt.qos":         np.zeros(n, dtype=int),     # QoS 0 = no ACK
        "mqtt.retain":      np.zeros(n, dtype=int),
        "mqtt.ver":         np.zeros(n, dtype=int),     # no CONNECT in flood
    })


# ── demo runner ──────────────────────────────────────────────────────────────

def run(model=None, encoder=None, standalone=True,
        n_windows=None, window_size=None):
    """
    Classify rolling windows of simulated flood traffic and trigger IPS.

    Args:
        model      : pre-loaded RandomForestClassifier (loaded from disk if None)
        encoder    : pre-loaded LabelEncoder for mqtt.hdrflags
        standalone : print header/footer when True; suppress when called from
                     run_all_attacks.py
        n_windows  : number of windows to evaluate (default: CLI arg or 5)
        window_size: packets per window (default: CLI arg or 20)

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
        print(f"  {BOLD}MQTT Publish Flood — Attack Simulation{RESET}")
        print(f"  Attacker : Aleena Tomy  |  Simulated IP: {ATTACKER_IP}")
        print("=" * 70)
        print(f"  {n_windows * window_size} flood packets  "
              f"({n_windows} windows × {window_size} packets/window)")
        print(f"  Each packet: PUBLISH QoS=0, frame.time_delta ≈ 0.001 s")
        print()

    logging.info("=== Flood simulation start — %d windows ===", n_windows)

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
            "FLOOD W%02d  verdict=%s  attack_pkts=%d/%d  prob=%.1f%%  correct=%s",
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

    logging.info("=== Flood simulation end ===")
    return {
        "attack_name":     "MQTT Publish Flood",
        "windows_correct": tally["correct"],
        "windows_total":   tally["total"],
        "n_blocked":       len(blocked),
    }


if __name__ == "__main__":
    run(standalone=True)
