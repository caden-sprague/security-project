"""
Unified 4-Attack IPS Demonstration
===================================
Loads the trained Random Forest model once, then runs four sequential attack
phases — one per team member — each targeting a different vulnerability in the
ICU IoT network. A normal-traffic baseline is shown first using the held-out
test set, so you can observe the contrast between legitimate and malicious
classifications.

Attack phases:
  1. Normal traffic baseline     (held-out test set)
  2. MQTT Publish Flood          (Aleena Tomy)       — 192.168.1.101
  3. MQTT Authentication Bypass  (Caden Sprague)     — 192.168.1.102
  4. MQTT Packet Crafting        (Devin Schupbach)   — 192.168.1.103
  5. CoAP Replay                 (Widyane Kasbi)     — 192.168.1.104

iptables DROP rules are created for each detected attack IP and cleaned up
at the end. On Windows or without root, the IPS action is logged/printed
but the actual iptables call is skipped gracefully.

Usage:
    python run_all_attacks.py
    python run_all_attacks.py --windows 3 --window-size 20
    sudo python run_all_attacks.py          # Linux: apply real iptables rules
"""

import os
import sys
import time
import logging
import subprocess
from datetime import datetime

import pandas as pd
import joblib

# Import each attack simulator as a module
from simulate_flood          import run as run_flood
from simulate_auth_bypass    import run as run_auth_bypass
from simulate_packet_crafting import run as run_packet_crafting
from simulate_coap_replay    import run as run_coap_replay

# ── config ───────────────────────────────────────────────────────────────────

MODEL_PATH = "rf_model.pkl"
LOG_PATH   = "ips_demo.log"

FEATURES = [
    "frame.time_delta", "tcp.time_delta",
    "tcp.flags.ack", "tcp.flags.push", "tcp.flags.reset",
    "mqtt.hdrflags", "mqtt.msgtype", "mqtt.qos", "mqtt.retain", "mqtt.ver",
]

GREEN = "\033[92m"
RED   = "\033[91m"
BOLD  = "\033[1m"
CYAN  = "\033[96m"
RESET = "\033[0m"

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    filemode="a",
)


# ── helpers ───────────────────────────────────────────────────────────────────

def _parse_int_arg(flag, default):
    try:
        return int(sys.argv[sys.argv.index(flag) + 1])
    except (ValueError, IndexError):
        return default


def _divider(title, colour=CYAN):
    bar = "-" * 70
    print(f"\n{colour}{BOLD}{bar}{RESET}")
    print(f"{colour}{BOLD}  {title}{RESET}")
    print(f"{colour}{BOLD}{bar}{RESET}\n")


def _run_normal_baseline(model, X_test, y_test, attack_col,
                          n_windows, window_size):
    """
    Classify n_windows rolling windows of normal traffic from the held-out
    test set to establish a baseline before the attack phases.
    """
    normal_X = X_test[y_test == 0].reset_index(drop=True)
    available = len(normal_X)

    _divider("Phase 1 — Normal Traffic Baseline (held-out test set)")
    print(f"  Showing {n_windows} windows of legitimate ICU sensor traffic\n")

    tally = {"correct": 0, "total": 0}

    for i in range(n_windows):
        start  = (i * window_size) % available
        end    = start + window_size
        if end <= available:
            window = normal_X.iloc[start:end]
        else:
            window = pd.concat([
                normal_X.iloc[start:],
                normal_X.iloc[:end - available],
            ])

        preds      = model.predict(window)
        probs      = model.predict_proba(window)
        attack_pct = preds.mean() * 100
        mean_prob  = probs[:, attack_col].mean() * 100
        verdict    = "ATTACK" if attack_pct >= 50 else "NORMAL"
        correct    = verdict == "NORMAL"

        tally["total"] += 1
        if correct:
            tally["correct"] += 1

        colour  = GREEN if verdict == "NORMAL" else RED
        outcome = f"{GREEN}CORRECT{RESET}" if correct else f"{RED}WRONG{RESET}"
        ts      = datetime.now().strftime("%H:%M:%S")

        print(f"[{ts}] Window {i+1:>2}  |  "
              f"True: NORMAL  "
              f"Verdict: {colour}{BOLD}{verdict}{RESET}  "
              f"Attack pkts: {int(preds.sum()):>2}/{window_size}  "
              f"Avg prob: {mean_prob:5.1f}%  "
              f"{outcome}")

        logging.info(
            "NORMAL W%02d  verdict=%s  attack_pkts=%d/%d  prob=%.1f%%",
            i + 1, verdict, int(preds.sum()), window_size, mean_prob,
        )

        time.sleep(0.4)

    print(f"\n  Windows correct : {tally['correct']}/{tally['total']}")
    return tally


def _print_summary(results, normal_tally):
    """Print the final per-attack and overall results table."""
    print()
    print("=" * 70)
    print(f"  {BOLD}Final Summary{RESET}")
    print("=" * 70)
    print(f"\n  {'Phase':<30}  {'Windows':>10}  {'Blocked':>8}")
    print(f"  {'-'*30}  {'-'*10}  {'-'*8}")

    total_correct = normal_tally["correct"]
    total_windows = normal_tally["total"]

    print(f"  {'Normal baseline':<30}  "
          f"{normal_tally['correct']:>4}/{normal_tally['total']:<5}  "
          f"{'n/a':>8}")

    all_blocked = set()
    for r in results:
        total_correct += r["windows_correct"]
        total_windows += r["windows_total"]
        all_blocked.update(range(r["n_blocked"]))  # unique IPs per attack

        label = f"{r['attack_name']}"
        print(f"  {label:<30}  "
              f"{r['windows_correct']:>4}/{r['windows_total']:<5}  "
              f"{r['n_blocked']:>8}")

    print(f"  {'-'*30}  {'-'*10}  {'-'*8}")
    print(f"  {'TOTAL':<30}  "
          f"{total_correct:>4}/{total_windows:<5}  "
          f"{sum(r['n_blocked'] for r in results):>8}")
    print()
    print(f"  Accuracy across all windows: "
          f"{total_correct/total_windows*100:.1f}%")
    print(f"  Log: {os.path.abspath(LOG_PATH)}")
    print("=" * 70)
    print()


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    n_windows   = _parse_int_arg("--windows", 5)
    window_size = _parse_int_arg("--window-size", 20)

    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"Model not found at '{MODEL_PATH}'. Run CreateRF.py first."
        )

    saved      = joblib.load(MODEL_PATH)
    model      = saved["model"]
    encoder    = saved["hdrflags_encoder"]
    X_test     = saved["X_test"]
    y_test     = saved["y_test"]
    attack_col = list(model.classes_).index(1)

    # ── header ────────────────────────────────────────────────────────────────
    print()
    print("=" * 70)
    print(f"  {BOLD}ICU IoT Intrusion Prevention System — 4-Attack Demo{RESET}")
    print(f"  Model    : Random Forest (max_depth=10, random_state=100)")
    print(f"  Dataset  : IoT Healthcare ICU (patient + env + attack traffic)")
    print(f"  Windows  : {n_windows} per phase x {window_size} packets each")
    print("=" * 70)

    logging.info("=" * 60)
    logging.info(
        "ALL-ATTACKS SESSION START  windows=%d  window_size=%d",
        n_windows, window_size,
    )
    logging.info("=" * 60)

    # ── Phase 1: normal baseline ───────────────────────────────────────────────
    normal_tally = _run_normal_baseline(
        model, X_test, y_test, attack_col, n_windows, window_size
    )

    # ── Phase 2–5: attack simulations ─────────────────────────────────────────
    attack_phases = [
        ("Phase 2 — MQTT Publish Flood     (Aleena Tomy)",      run_flood),
        ("Phase 3 — MQTT Auth Bypass       (Caden Sprague)",    run_auth_bypass),
        ("Phase 4 — MQTT Packet Crafting   (Devin Schupbach)",  run_packet_crafting),
        ("Phase 5 — CoAP Replay            (Widyane Kasbi)",    run_coap_replay),
    ]

    results = []
    for title, attack_fn in attack_phases:
        _divider(title)
        result = attack_fn(
            model=model,
            encoder=encoder,
            X_test=X_test,
            y_test=y_test,
            standalone=False,
            n_windows=n_windows,
            window_size=window_size,
        )
        results.append(result)
        print(f"\n  Windows correct : {result['windows_correct']}/{result['windows_total']}")
        print(f"  IPs blocked     : {result['n_blocked']}")
        time.sleep(0.5)

    # ── final summary ─────────────────────────────────────────────────────────
    _print_summary(results, normal_tally)

    logging.info("=" * 60)
    logging.info("ALL-ATTACKS SESSION END")
    logging.info("=" * 60)


if __name__ == "__main__":
    main()
