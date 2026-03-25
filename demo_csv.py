"""
IPS Demo: classify rolling windows from the held-out test split and block
attacker IPs via iptables whenever an attack window is detected.

Simulated attacker IPs represent IoT devices in the ICU environment.
Real iptables rules are created and cleaned up at the end of the demo,
showing the active IPS response alongside the detection output.

Usage:
    sudo python3 demo_csv.py [--debug]

Requires root (sudo) for iptables.

Flags:
    --debug   Prompt for confirmation before every iptables change.
"""

import sys
import os
import time
import logging
import subprocess
from datetime import datetime

import pandas as pd
import joblib

MODEL_PATH  = "rf_model.pkl"
LOG_PATH    = "ips_demo.log"
DEBUG       = "--debug" in sys.argv
WINDOW_SIZE = 20
N_WINDOWS   = 5

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# ANSI colour codes
GREEN = "\033[92m"
RED   = "\033[91m"
BOLD  = "\033[1m"
RESET = "\033[0m"

FEATURES = [
    "frame.time_delta", "tcp.time_delta",
    "tcp.flags.ack", "tcp.flags.push", "tcp.flags.reset",
    "mqtt.hdrflags", "mqtt.msgtype", "mqtt.qos", "mqtt.retain", "mqtt.ver",
]

# Simulated attacker IPs — represent malicious IoT devices in the ICU network
ATTACKER_POOL = [
    "192.168.1.101",
    "192.168.1.102",
    "192.168.1.103",
    "192.168.1.104",
    "192.168.1.105",
]

blocked_ips = set()  # type: set


# ── iptables helpers ────────────────────────────────────────────────────────

def confirm(prompt: str) -> bool:
    """In debug mode, ask the user before proceeding. Always returns True otherwise."""
    if not DEBUG:
        return True
    ans = input(f"  {BOLD}[DEBUG]{RESET} {prompt} [y/N]: ").strip().lower()
    return ans == "y"


def block_ip(ip: str):
    if ip in blocked_ips:
        return
    if not confirm(f"Apply: iptables -I INPUT -s {ip} -j DROP?"):
        print(f"  [DEBUG] Skipped block for {ip}")
        logging.info("DEBUG SKIP BLOCK  %s", ip)
        return
    result = subprocess.run(
        ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        blocked_ips.add(ip)
        print(f"  {RED}{BOLD}[BLOCKED]{RESET}  iptables -I INPUT -s {ip} -j DROP")
        logging.warning("BLOCKED   iptables -I INPUT -s %s -j DROP", ip)
    else:
        msg = result.stderr.strip()
        print(f"  [!] iptables failed for {ip}: {msg}")
        logging.error("BLOCK FAILED  ip=%s  error=%s", ip, msg)


def show_iptables(heading: str):
    print(f"\n[*] {heading}")
    result = subprocess.run(
        ["iptables", "-L", "INPUT", "-n", "--line-numbers"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            print(f"    {line}")
    else:
        print(f"    [!] Could not read iptables: {result.stderr.strip()}")
    print()


def unblock_all():
    if not blocked_ips:
        return
    print(f"\n[*] Flushing {len(blocked_ips)} iptables rule(s)...")
    for ip in list(blocked_ips):
        if not confirm(f"Apply: iptables -D INPUT -s {ip} -j DROP?"):
            print(f"  [DEBUG] Skipped unblock for {ip}")
            logging.info("DEBUG SKIP UNBLOCK  %s", ip)
            continue
        subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True
        )
        print(f"  {GREEN}[UNBLOCKED]{RESET}  {ip}")
        logging.info("UNBLOCKED  %s", ip)


# ── detection ───────────────────────────────────────────────────────────────

def classify_window(X, model, attack_col):
    preds            = model.predict(X)
    probs            = model.predict_proba(X)
    attack_pct       = preds.mean() * 100
    mean_attack_prob = probs[:, attack_col].mean() * 100
    verdict          = "ATTACK" if attack_pct >= 50 else "NORMAL"
    return verdict, attack_pct, mean_attack_prob, int(preds.sum())


def run_windows(label, X_pool, model, attack_col, n_windows, window_size, tally):
    available = len(X_pool)
    for i in range(n_windows):
        start  = (i * window_size) % available
        end    = start + window_size
        if end <= available:
            window = X_pool.iloc[start:end]
        else:
            window = pd.concat([X_pool.iloc[start:], X_pool.iloc[:end - available]])

        verdict, attack_pct, mean_prob, n_attack = classify_window(
            window, model, attack_col
        )
        correct = verdict == label
        tally["total"] += 1
        if correct:
            tally["correct"] += 1

        colour      = GREEN if verdict == "NORMAL" else RED
        verdict_str = f"{colour}{BOLD}{verdict}{RESET}"
        outcome_str = f"{GREEN}CORRECT{RESET}" if correct else f"{RED}*** WRONG ***{RESET}"
        ts          = datetime.now().strftime("%H:%M:%S")

        print(f"[{ts}] Window {tally['total']:>2}  |  "
              f"True: {label:<6}  "
              f"Verdict: {verdict_str:<6}  "
              f"Attack pkts: {n_attack:>2}/{window_size}  "
              f"Avg attack prob: {mean_prob:5.1f}%  "
              f"{outcome_str}")

        logging.info(
            "WINDOW %02d  true=%-6s  verdict=%-6s  attack_pkts=%d/%d  "
            "avg_attack_prob=%.1f%%  correct=%s",
            tally["total"], label, verdict, n_attack, window_size,
            mean_prob, correct
        )

        # IPS response: block a simulated attacker IP for each attack window
        if verdict == "ATTACK":
            ip = ATTACKER_POOL[tally["total"] % len(ATTACKER_POOL)]
            block_ip(ip)

        time.sleep(0.6)


def print_feature_importance(model):
    importances = sorted(
        zip(FEATURES, model.feature_importances_),
        key=lambda x: x[1], reverse=True
    )
    print(f"  {'Feature':<22}  Importance")
    print(f"  {'-'*22}  ----------")
    for feat, imp in importances[:3]:
        bar = "#" * int(imp * 60)
        print(f"  {feat:<22}  {imp:.4f}  {bar}")


def full_test_metrics(X_test, y_test, model):
    preds = model.predict(X_test)
    tp = int(((preds == 1) & (y_test == 1)).sum())
    tn = int(((preds == 0) & (y_test == 0)).sum())
    fp = int(((preds == 1) & (y_test == 0)).sum())
    fn = int(((preds == 0) & (y_test == 1)).sum())
    accuracy  = (tp + tn) / len(y_test) * 100
    precision = tp / (tp + fp) * 100 if (tp + fp) else 0
    recall    = tp / (tp + fn) * 100 if (tp + fn) else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    return accuracy, precision, recall, f1, tp, tn, fp, fn


# ── main ────────────────────────────────────────────────────────────────────

def main():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model not found at '{MODEL_PATH}'. Run createRF.py first.")

    saved      = joblib.load(MODEL_PATH)
    model      = saved["model"]
    X_test     = saved["X_test"]
    y_test     = saved["y_test"]
    attack_col = list(model.classes_).index(1)

    normal_X = X_test[y_test == 0].reset_index(drop=True)
    attack_X = X_test[y_test == 1].reset_index(drop=True)

    print()
    print("=" * 70)
    print(f"  {BOLD}ICU MQTT Intrusion Prevention System — Demo{RESET}")
    print("=" * 70)
    print(f"  Test split : {len(X_test):,} packets (never seen during training)")
    print(f"  Window size: {WINDOW_SIZE} packets   |   Windows per class: {N_WINDOWS}")
    if DEBUG:
        print(f"  {BOLD}Mode       : DEBUG — confirming each iptables change{RESET}")
    print()
    print("  Top 3 features by importance:")
    print_feature_importance(model)
    print("=" * 70)
    print()

    tally = {"correct": 0, "total": 0}

    logging.info("=" * 60)
    logging.info("SESSION START  window_size=%d  n_windows=%d", WINDOW_SIZE, N_WINDOWS)
    logging.info("=" * 60)

    show_iptables("iptables INPUT chain — before demo")

    completed = False
    try:
        print(f"{BOLD}--- Normal traffic (environmentMonitoring / patientMonitoring) ---{RESET}\n")
        run_windows("NORMAL", normal_X, model, attack_col, N_WINDOWS, WINDOW_SIZE, tally)

        print()
        print(f"{BOLD}--- Attack traffic (flood / connection exhaustion) ---{RESET}\n")
        run_windows("ATTACK", attack_X, model, attack_col, N_WINDOWS, WINDOW_SIZE, tally)

        completed = True
    finally:
        show_iptables("iptables INPUT chain — after attacks detected")
        unblock_all()
        show_iptables("iptables INPUT chain — after cleanup")

    if not completed:
        return

    accuracy, precision, recall, f1, tp, tn, fp, fn = full_test_metrics(
        X_test, y_test, model
    )
    w = max(len(str(tp)), len(str(fp)), len(str(fn)), len(str(tn)))

    logging.info("=" * 60)
    logging.info(
        "SESSION END  windows=%d/%d correct  ips_blocked=%d  "
        "accuracy=%.2f%%  precision=%.2f%%  recall=%.2f%%  f1=%.2f%%",
        tally["correct"], tally["total"], len(blocked_ips),
        accuracy, precision, recall, f1
    )
    logging.info("=" * 60)
    logging.info("Log written to %s", os.path.abspath(LOG_PATH))

    print()
    print("=" * 70)
    print(f"  {BOLD}Results{RESET}")
    print("=" * 70)
    print(f"  Windows correct  : {tally['correct']} / {tally['total']}")
    print(f"  IPs blocked      : {len(blocked_ips)} unique attacker(s) identified")
    print(f"  Log file         : {os.path.abspath(LOG_PATH)}")
    print()
    print("  Full test-set metrics:")
    print(f"    Accuracy  : {accuracy:.2f}%")
    print(f"    Precision : {precision:.2f}%")
    print(f"    Recall    : {recall:.2f}%")
    print(f"    F1 Score  : {f1:.2f}%")
    print()
    print(f"  Confusion matrix ({len(X_test):,} packets):")
    print(f"")
    print(f"                       Predicted")
    print(f"                  {'NORMAL':<{w+4}}  {'ATTACK':<{w+4}}")
    print(f"  Actual NORMAL   {GREEN}TN: {tn:<{w}}{RESET}  {RED}FP: {fp:<{w}}{RESET}  (correctly allowed / false alarms)")
    print(f"  Actual ATTACK   {RED}FN: {fn:<{w}}{RESET}  {GREEN}TP: {tp:<{w}}{RESET}  (missed attacks  / correctly blocked)")
    print("=" * 70)
    print()


if __name__ == "__main__":
    main()
