"""
Demo: classify samples from the held-out test split saved in rf_model.pkl.

The test set is the 30% of data the model never saw during training
(split in createRF.py with random_state=100).

Usage:
    python3 demo_csv.py [n_samples]

Default: 20 samples per class.
"""

import sys
import os

import joblib

MODEL_PATH = "rf_model.pkl"

N_SAMPLES = int(sys.argv[1]) if len(sys.argv) > 1 else 20


def classify(name, X, y_true, model, attack_col):
    preds = model.predict(X)
    probs = model.predict_proba(X)

    attack_pct       = preds.mean() * 100
    mean_attack_prob = probs[:, attack_col].mean() * 100
    verdict          = "ATTACK" if attack_pct >= 50 else "NORMAL"
    correct          = verdict == name

    print("=" * 42)
    print(f"  True class     : {name}")
    print(f"  Verdict        : {verdict}  ({'CORRECT' if correct else 'WRONG'})")
    print(f"  Attack pkts    : {int(preds.sum())} / {len(preds)}  ({attack_pct:.1f}%)")
    print(f"  Avg attack prob: {mean_attack_prob:.1f}%")
    print("=" * 42)
    print()
    return correct


def main():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model not found at '{MODEL_PATH}'. Run createRF.py first.")

    saved      = joblib.load(MODEL_PATH)
    model      = saved["model"]
    X_test     = saved["X_test"]
    y_test     = saved["y_test"]
    attack_col = list(model.classes_).index(1)

    # Separate the held-out test set by true label
    normal_X = X_test[y_test == 0].sample(min(N_SAMPLES, (y_test == 0).sum()), random_state=42)
    attack_X = X_test[y_test == 1].sample(min(N_SAMPLES, (y_test == 1).sum()), random_state=42)

    print(f"[*] Using held-out test split ({len(X_test)} total packets, never seen during training)")
    print(f"[*] Sampling {len(normal_X)} normal / {len(attack_X)} attack packets\n")

    results = []
    results.append(classify("NORMAL", normal_X, None, model, attack_col))
    results.append(classify("ATTACK", attack_X, None, model, attack_col))

    print(f"[*] {sum(results)}/{len(results)} classes correctly identified")


if __name__ == "__main__":
    main()
