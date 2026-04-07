"""
train_models.py — Train and serialise all 3 security ML classifiers.

Models trained:
  1. Malware Classifier     — RandomForestClassifier  (2381 features)
  2. IDS Classifier         — GradientBoostingClassifier (41 features)
  3. Phishing Classifier    — LogisticRegression        (30 features)

All models must reach ≥80 % test accuracy before saving.
Test subsets are also saved as .npy arrays for use by attack_runner.py.

Usage:
    python train_models.py
"""

import os
import logging

import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import StandardScaler

from loaders.ember_loader import load_ember_data
from loaders.nslkdd_loader import load_nslkdd_data
from loaders.phishing_loader import load_phishing_data

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger(__name__)

RANDOM_STATE = 42
MODELS_DIR = "models"
MIN_ACCURACY = 0.80


def ensure_dirs() -> None:
    os.makedirs(MODELS_DIR, exist_ok=True)
    os.makedirs("data", exist_ok=True)
    os.makedirs("results", exist_ok=True)


def _save_test_split(tag: str, X_test: np.ndarray, y_test: np.ndarray) -> None:
    np.save(os.path.join(MODELS_DIR, f"{tag}_test_X.npy"), X_test.astype(np.float32))
    np.save(os.path.join(MODELS_DIR, f"{tag}_test_y.npy"), y_test.astype(np.int64))
    log.info("  Saved %s test split (%d samples).", tag, len(y_test))


def train_model(tag: str, clf, X_train, X_test, y_train, y_test, scaler=None):
    """Fit *clf*, evaluate, save, and return test accuracy."""
    log.info("Training %s …", tag)
    clf.fit(X_train, y_train)

    preds = clf.predict(X_test)
    acc = accuracy_score(y_test, preds)
    log.info("  %s test accuracy: %.4f", tag, acc)

    if acc < MIN_ACCURACY:
        log.warning(
            "  %s accuracy %.4f is below the %.0f%% threshold!",
            tag, acc, MIN_ACCURACY * 100,
        )

    model_path = os.path.join(MODELS_DIR, f"{tag}.pkl")
    joblib.dump(clf, model_path)
    log.info("  Saved model → %s", model_path)

    if scaler is not None:
        scaler_path = os.path.join(MODELS_DIR, f"{tag}_scaler.pkl")
        joblib.dump(scaler, scaler_path)
        log.info("  Saved scaler → %s", scaler_path)

    return acc


def main() -> None:
    np.random.seed(RANDOM_STATE)
    ensure_dirs()

    # ------------------------------------------------------------------
    # 1. Malware Classifier — RandomForest on EMBER-style PE features
    # ------------------------------------------------------------------
    log.info("=== [1/3] Malware Classifier (RandomForest, 2381 features) ===")
    X, y = load_ember_data(RANDOM_STATE)
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
    )
    clf1 = RandomForestClassifier(
        n_estimators=100, random_state=RANDOM_STATE, n_jobs=-1
    )
    acc1 = train_model("malware_classifier", clf1, X_tr, X_te, y_tr, y_te)
    _save_test_split("malware_classifier", X_te, y_te)

    # ------------------------------------------------------------------
    # 2. IDS Classifier — GradientBoosting on NSL-KDD-style features
    # ------------------------------------------------------------------
    log.info("=== [2/3] IDS Classifier (GradientBoosting, 41 features) ===")
    X2, y2 = load_nslkdd_data(RANDOM_STATE)
    X2_tr, X2_te, y2_tr, y2_te = train_test_split(
        X2, y2, test_size=0.2, random_state=RANDOM_STATE, stratify=y2
    )
    clf2 = GradientBoostingClassifier(
        n_estimators=100, random_state=RANDOM_STATE
    )
    acc2 = train_model("ids_classifier", clf2, X2_tr, X2_te, y2_tr, y2_te)
    _save_test_split("ids_classifier", X2_te, y2_te)

    # ------------------------------------------------------------------
    # 3. Phishing Classifier — LogisticRegression on UCI Phishing features
    # ------------------------------------------------------------------
    log.info("=== [3/3] Phishing Classifier (LogisticRegression, 30 features) ===")
    X3, y3 = load_phishing_data(RANDOM_STATE)
    X3_tr, X3_te, y3_tr, y3_te = train_test_split(
        X3, y3, test_size=0.2, random_state=RANDOM_STATE, stratify=y3
    )
    # Logistic regression benefits from feature scaling
    scaler = StandardScaler()
    X3_tr_s = scaler.fit_transform(X3_tr).astype(np.float32)
    X3_te_s = scaler.transform(X3_te).astype(np.float32)
    clf3 = LogisticRegression(max_iter=1000, random_state=RANDOM_STATE)
    acc3 = train_model(
        "phishing_classifier", clf3, X3_tr_s, X3_te_s, y3_tr, y3_te, scaler=scaler
    )
    _save_test_split("phishing_classifier", X3_te_s, y3_te)

    # ------------------------------------------------------------------
    log.info("=== Training complete ===")
    log.info("  Malware   accuracy: %.4f  %s", acc1, "✓" if acc1 >= MIN_ACCURACY else "✗ BELOW THRESHOLD")
    log.info("  IDS       accuracy: %.4f  %s", acc2, "✓" if acc2 >= MIN_ACCURACY else "✗ BELOW THRESHOLD")
    log.info("  Phishing  accuracy: %.4f  %s", acc3, "✓" if acc3 >= MIN_ACCURACY else "✗ BELOW THRESHOLD")
    log.info("Run `python attack_runner.py` or use the dashboard to run benchmarks.")


if __name__ == "__main__":
    main()
