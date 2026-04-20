"""
MQTT Packet Crafting Attack Simulator
Attacker: Devin Schupbach

The MQTT Packet Crafting attack sends specially crafted, malformed MQTT packets
designed to crash or destabilise the MQTT broker. The attacker establishes a
TCP connection, then publishes messages *before* sending a valid CONNECT
request, violating the MQTT protocol state machine. The broker rejects these
with TCP RST (reset) frames. In large volumes, this can cause denial-of-service
or expose memory-corruption vulnerabilities in the broker.

Attack signature (10-feature profile):
  - frame.time_delta  : 0.0001–0.01 s (rapid crafted-packet bursts)
  - tcp.time_delta    : 0.0001–0.05 s (fast retries after RST)
  - tcp.flags.ack     : mix of 0/1 (resets interrupt the ACK sequence)
  - tcp.flags.push    : mix of 0/1 (malformed data pushes)
  - tcp.flags.reset=1 : HIGH (broker/server resets malformed connections)
  - mqtt.hdrflags=6   : DUP PUBLISH QoS=1 (0x3a — malformed duplicate flag)
  - mqtt.msgtype      : mix of 0 (raw TCP/malformed) and 3 (PUBLISH before CONNECT)
  - mqtt.qos=1        : QoS=1 used in crafted packets (unexpected for pre-CONNECT)
  - mqtt.retain=0
  - mqtt.ver=0        : no valid CONNECT sent, so version field is 0

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

import numpy as np
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


# ── traffic generator ────────────────────────────────────────────────────────

def generate(n, encoder):
    """
    Return a DataFrame of n synthetic MQTT Packet Crafting packets.

    The key distinguishing feature is tcp.flags.reset=1 on a significant
    fraction of packets — the broker is actively resetting connections that
    it receives malformed MQTT packets on. Normal ICU traffic has reset=0
    on every single packet, making this a very strong attack indicator.
    """
    rng = np.random.default_rng(13)

    classes        = list(encoder.classes_)
    # DUP PUBLISH QoS=1: hdrflags '0x0000003a' — malformed duplicate marker
    dup_pub_hdr    = classes.index("0x0000003a") if "0x0000003a" in classes else 0
    # Some packets are raw TCP (no MQTT layer): hdrflags '0'
    no_mqtt_hdr    = classes.index("0") if "0" in classes else 0

    # ~40 % of packets trigger a TCP RST (broker rejecting malformed frames)
    has_rst        = rng.random(n) < 0.40
    # ~60 % carry MQTT data (PUBLISH before CONNECT); 40 % are raw TCP frames
    has_mqtt       = rng.random(n) > 0.40

    return pd.DataFrame({
        # Fast retry loop after each RST: 0.0001–0.01 s
        "frame.time_delta": rng.uniform(0.0001, 0.01, n),
        "tcp.time_delta":   rng.uniform(0.0001, 0.05, n),
        # RST packets break the normal ACK flow
        "tcp.flags.ack":    (~has_rst).astype(int),
        "tcp.flags.push":   np.where(has_mqtt & ~has_rst, 1, 0).astype(int),
        # tcp.flags.reset=1 is the strongest single indicator of this attack
        "tcp.flags.reset":  has_rst.astype(int),
        # DUP PUBLISH on MQTT frames; raw '0' on non-MQTT frames
        "mqtt.hdrflags":    np.where(has_mqtt, dup_pub_hdr, no_mqtt_hdr).astype(int),
        # PUBLISH (3) on MQTT frames; 0 on raw TCP frames
        "mqtt.msgtype":     np.where(has_mqtt, 3, 0).astype(int),
        # QoS=1 used in the crafted packets
        "mqtt.qos":         np.where(has_mqtt, 1, 0).astype(int),
        "mqtt.retain":      np.zeros(n, dtype=int),
        # No valid CONNECT was sent, so version = 0
        "mqtt.ver":         np.zeros(n, dtype=int),
    })


# ── demo runner ──────────────────────────────────────────────────────────────

def run(model=None, encoder=None, standalone=True,
        n_windows=None, window_size=None):
    """
    Classify rolling windows of simulated packet crafting traffic and trigger IPS.

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
