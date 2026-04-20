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

Attack signature (10-feature profile):
  - frame.time_delta  : 0.001–0.5 s (replayed at varying intervals)
  - tcp.time_delta    : 0.0  (UDP — no TCP; this field is 0 for non-TCP flows)
  - tcp.flags.ack=0   : UDP has no TCP ACK handshake
  - tcp.flags.push=0  : UDP has no TCP PSH flag
  - tcp.flags.reset=0 : UDP has no TCP RST
  - mqtt.hdrflags=0   : no MQTT layer — CoAP uses its own binary header
  - mqtt.msgtype=0    : no MQTT message type (CoAP packets)
  - mqtt.qos=0        : no QoS (CoAP uses its own reliability model)
  - mqtt.retain=0
  - mqtt.ver=0        : no MQTT version

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

import numpy as np
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


# ── traffic generator ────────────────────────────────────────────────────────

def generate(n, encoder):
    """
    Return a DataFrame of n synthetic CoAP Replay packets.

    CoAP runs over UDP (ip.proto=17). The tshark capture pipeline fills all
    tcp.* and mqtt.* fields with 0 for UDP flows. This gives CoAP replay
    traffic a very distinctive all-zero pattern across the MQTT/TCP feature
    columns — completely unlike normal MQTT ICU traffic where tcp.flags.ack=1
    and mqtt.msgtype ≥ 1 on every packet.

    The attacker replays at irregular intervals to mimic legitimate environmental
    sensor readings, which is why frame.time_delta spans a wider range (0.001–0.5 s)
    compared to the MQTT flood.
    """
    rng = np.random.default_rng(99)

    # All CoAP packets have hdrflags='0' (no MQTT layer) → encoded index 0
    classes     = list(encoder.classes_)
    no_mqtt_hdr = classes.index("0") if "0" in classes else 0

    return pd.DataFrame({
        # Replayed at irregular intervals mimicking normal sensor cadence
        "frame.time_delta": rng.uniform(0.001, 0.5, n),
        # UDP flow — tcp.time_delta is 0 (no TCP session tracking)
        "tcp.time_delta":   np.zeros(n, dtype=float),
        # UDP: no TCP flags at all
        "tcp.flags.ack":    np.zeros(n, dtype=int),
        "tcp.flags.push":   np.zeros(n, dtype=int),
        "tcp.flags.reset":  np.zeros(n, dtype=int),
        # No MQTT application layer
        "mqtt.hdrflags":    np.full(n, no_mqtt_hdr, dtype=int),
        "mqtt.msgtype":     np.zeros(n, dtype=int),
        "mqtt.qos":         np.zeros(n, dtype=int),
        "mqtt.retain":      np.zeros(n, dtype=int),
        "mqtt.ver":         np.zeros(n, dtype=int),
    })


# ── demo runner ──────────────────────────────────────────────────────────────

def run(model=None, encoder=None, standalone=True,
        n_windows=None, window_size=None):
    """
    Classify rolling windows of simulated CoAP replay traffic and trigger IPS.

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
