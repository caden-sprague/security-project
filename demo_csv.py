"""
Demo: simulate rolling detection windows using the held-out test split.

Classifies N_WINDOWS windows of normal traffic, then N_WINDOWS windows of
attack traffic, mimicking the live demo flow. Data is from the 10% test split
that was never seen during training.

Usage:
    python3 demo_csv.py [window_size] [n_windows]

Defaults: 20 packets per window, 5 windows per class.
"""

import sys
import os
import time
from datetime import datetime

import pandas as pd
import joblib

MODEL_PATH  = "rf_model.pkl"
WINDOW_SIZE = int(sys.argv[1]) if len(sys.argv) > 1 else 20
N_WINDOWS   = int(sys.argv[2]) if len(sys.argv) > 2 else 5

# ANSI colour codes
GREEN  = "\033[92m"
RED    = "\033[91m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

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

        colour       = GREEN if verdict == "NORMAL" else RED
        verdict_str  = f"{colour}{BOLD}{verdict}{RESET}"
        outcome_str  = f"{GREEN}CORRECT{RESET}" if correct else f"{RED}*** WRONG ***{RESET}"
        ts           = datetime.now().strftime("%H:%M:%S")

        print(f"[{ts}] Window {tally['total']:>2}  |  "
              f"True: {label:<6}  "
              f"Verdict: {verdict_str:<6}  "
              f"Attack pkts: {n_attack:>2}/{window_size}  "
              f"Avg attack prob: {mean_prob:5.1f}%  "
              f"{outcome_str}")
        time.sleep(0.6)


def print_feature_importance(model):
    importances = sorted(
        zip(FEATURES, model.feature_importances_),
        key=lambda x: x[1],
        reverse=True
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
    print(f"  {BOLD}ICU MQTT Intrusion Detection — Dataset Demo{RESET}")
    print("=" * 70)
    print(f"  Test split : {len(X_test):,} packets (never seen during training)")
    print(f"  Window size: {WINDOW_SIZE} packets   |   Windows per class: {N_WINDOWS}")
    print()
    print("  Top 3 features by importance:")
    print_feature_importance(model)
    print("=" * 70)
    print()

    tally = {"correct": 0, "total": 0}

    print(f"{BOLD}--- Normal traffic (environmentMonitoring / patientMonitoring) ---{RESET}\n")
    run_windows("NORMAL", normal_X, model, attack_col, N_WINDOWS, WINDOW_SIZE, tally)

    print()
    print(f"{BOLD}--- Attack traffic (flood / connection exhaustion) ---{RESET}\n")
    run_windows("ATTACK", attack_X, model, attack_col, N_WINDOWS, WINDOW_SIZE, tally)

    accuracy, precision, recall, f1, tp, tn, fp, fn = full_test_metrics(
        X_test, y_test, model
    )

    w = max(len(str(tp)), len(str(fp)), len(str(fn)), len(str(tn)))

    print()
    print("=" * 70)
    print(f"  {BOLD}Results{RESET}")
    print("=" * 70)
    print(f"  Windows correct : {tally['correct']} / {tally['total']}")
    print()
    print("  Full test-set metrics:")
    print(f"    Accuracy  : {accuracy:.2f}%")
    print(f"    Precision : {precision:.2f}%")
    print(f"    Recall    : {recall:.2f}%")
    print(f"    F1 Score  : {f1:.2f}%")
    print()
    print(f"  Confusion matrix ({len(X_test):,} packets):")
    print(f"                  Predicted")
    print(f"                  {'NORMAL':<{w+2}}  {'ATTACK':<{w+2}}")
    print(f"  Actual NORMAL   {GREEN}{tn:<{w+2}}{RESET}  {RED}{fp:<{w+2}}{RESET}")
    print(f"  Actual ATTACK   {RED}{fn:<{w+2}}{RESET}  {GREEN}{tp:<{w+2}}{RESET}")
    print("=" * 70)
    print()


if __name__ == "__main__":
    main()
