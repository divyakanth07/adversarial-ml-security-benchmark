"""
attack_runner.py — Extended adversarial attack engine for the Adversarial ML Toolkit.

Attacks (all via IBM ART):
  • FGSM       — FastGradientMethod   (white-box via surrogate for tree models)
  • HopSkipJump— HopSkipJump         (black-box, label-only access)
  • ZooAttack  — ZooAttack           (black-box, probability access)  [FIXED: batch_size=1]
  • C&W        — CarliniL2Method     (white-box via surrogate, minimum distortion)
  • DeepFool   — DeepFool            (white-box via surrogate, minimal perturbation)

New in v2:
  • Threat scenario profiles    (ATTACK_PROFILES constant)
  • Domain-realistic constraints (apply_constraints from feature_constraints.py)
  • Query budget estimation      (n_queries field in every result)
  • Epsilon sweep                (run_epsilon_sweep)
  • Adversarial training defense (apply_defense)
  • Run history                  (auto-appended to results/run_history.json)

Gradient fix:
  RandomForest and GradientBoosting do not expose gradients to ART.
  For FGSM / C&W / DeepFool we train a lightweight surrogate SGDClassifier on
  the same training data and run the attack against it — a realistic transfer-
  attack scenario.  Evaluation is always performed on the original model.

Usage:
    python attack_runner.py                              # all 15 combos (5 attacks × 3 models)
    python attack_runner.py --model ids --attack fgsm   # single combo
    python attack_runner.py --sweep --model malware      # epsilon sweep
    python attack_runner.py --defend --model phishing    # adversarial training
    python attack_runner.py --constrain                  # realistic feature constraints
"""

import os
import json
import logging
import argparse
import time
import threading
import warnings
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

# Suppress ART's PyTorch-not-found UserWarning (we don't use those modules)
warnings.filterwarnings("ignore", message="PyTorch not found")

import numpy as np
import joblib
from sklearn.base import clone
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import StratifiedShuffleSplit, train_test_split

from art.estimators.classification import SklearnClassifier
from art.attacks.evasion import (
    FastGradientMethod,
    HopSkipJump,
    ZooAttack,
    CarliniL2Method,
    DeepFool,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger(__name__)

RANDOM_STATE = 42
MODELS_DIR   = "models"
RESULTS_DIR  = "results"

RESULTS_FILE  = os.path.join(RESULTS_DIR, "benchmark_results.json")
PROGRESS_FILE = os.path.join(RESULTS_DIR, "progress.json")
HISTORY_FILE  = os.path.join(RESULTS_DIR, "run_history.json")
DEFENSE_FILE  = os.path.join(RESULTS_DIR, "defense_results.json")

_progress_lock = threading.Lock()

CLIP_MIN = -10.0
CLIP_MAX  =  10.0

# ---------------------------------------------------------------------------
# Default sample sizes (tuned for runtime feasibility)
# ---------------------------------------------------------------------------

ATTACK_SAMPLE_SIZES: Dict[str, int] = {
    "fgsm":        500,
    "hopskipjump":  50,   # each sample ≈ hundreds of model queries
    "zoo":          30,   # coordinate-wise gradient estimation — very slow
    "cw":           30,   # iterative optimisation + binary search
    "deepfool":    200,   # fast per-sample but needs many iterations
}

# Malware has 2381 features → each tree query is expensive; reduce samples
MODEL_SAMPLE_OVERRIDES: Dict[str, Dict[str, int]] = {
    "malware": {"hopskipjump": 20, "zoo": 10, "cw": 10, "deepfool": 100},
}

# ---------------------------------------------------------------------------
# Threat scenario profiles
# ---------------------------------------------------------------------------

ATTACK_PROFILES: Dict[str, dict] = {
    "script_kiddie": {
        "label":       "Script Kiddie",
        "icon":        "🎭",
        "attack":      "fgsm",
        "description": "Opportunistic attacker using publicly available tools. High-epsilon, "
                       "noisy perturbation — not stealthy, but cheap and fast.",
        "params":      {"eps": 0.30},
    },
    "insider_threat": {
        "label":       "Insider Threat",
        "icon":        "🕵",
        "attack":      "fgsm",
        "description": "Privileged user with full model access. Low-epsilon, precise perturbation "
                       "— hard to detect because changes are minimal.",
        "params":      {"eps": 0.02},
    },
    "api_scraper": {
        "label":       "API Scraper",
        "icon":        "🤖",
        "attack":      "hopskipjump",
        "description": "External attacker querying a deployed API endpoint (receives only "
                       "predicted labels, no probabilities). Realistic production threat.",
        "params":      {},
    },
    "nation_state": {
        "label":       "Nation-State APT",
        "icon":        "🌐",
        "attack":      "zoo",
        "description": "Well-resourced, patient attacker with probability access. Optimises "
                       "each adversarial example carefully to minimise detection risk.",
        "params":      {},
    },
    "precision_strike": {
        "label":       "Precision Strike",
        "icon":        "🎯",
        "attack":      "cw",
        "description": "Finds the minimum-distortion adversarial example (Carlini & Wagner L2). "
                       "Represents a sophisticated attacker optimising for stealth.",
        "params":      {},
    },
    "boundary_probe": {
        "label":       "Boundary Probe",
        "icon":        "🔬",
        "attack":      "deepfool",
        "description": "Seeks the shortest path to the model's decision boundary (DeepFool). "
                       "Useful for measuring true model fragility at minimal cost.",
        "params":      {},
    },
    "custom": {
        "label":       "Custom",
        "icon":        "⚙",
        "attack":      "fgsm",
        "description": "Define your own attack type and parameters.",
        "params":      {"eps": 0.05},
    },
}

# ---------------------------------------------------------------------------
# Model configurations
# ---------------------------------------------------------------------------

MODELS_CONFIG: Dict[str, dict] = {
    "malware": {
        "model_path":  os.path.join(MODELS_DIR, "malware_classifier.pkl"),
        "scaler_path": None,
        "X_path":      os.path.join(MODELS_DIR, "malware_classifier_test_X.npy"),
        "y_path":      os.path.join(MODELS_DIR, "malware_classifier_test_y.npy"),
        "loader":      "ember",
    },
    "ids": {
        "model_path":  os.path.join(MODELS_DIR, "ids_classifier.pkl"),
        "scaler_path": None,
        "X_path":      os.path.join(MODELS_DIR, "ids_classifier_test_X.npy"),
        "y_path":      os.path.join(MODELS_DIR, "ids_classifier_test_y.npy"),
        "loader":      "nslkdd",
    },
    "phishing": {
        "model_path":  os.path.join(MODELS_DIR, "phishing_classifier.pkl"),
        "scaler_path": os.path.join(MODELS_DIR, "phishing_classifier_scaler.pkl"),
        "X_path":      os.path.join(MODELS_DIR, "phishing_classifier_test_X.npy"),
        "y_path":      os.path.join(MODELS_DIR, "phishing_classifier_test_y.npy"),
        "loader":      "phishing",
    },
}

VALID_ATTACKS = {"fgsm", "hopskipjump", "zoo", "cw", "deepfool"}
_GRADIENT_ATTACKS = {"fgsm", "cw", "deepfool"}   # require surrogate on tree models
_ATTACK_ORDER     = ["fgsm", "hopskipjump", "zoo", "cw", "deepfool"]


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

def _write_progress(data: dict) -> None:
    """Write benchmark progress to progress.json. Never raises."""
    try:
        os.makedirs(RESULTS_DIR, exist_ok=True)
        with _progress_lock:
            with open(PROGRESS_FILE, "w") as fh:
                json.dump(data, fh)
    except Exception:
        pass


def _stratified_subset(
    X: np.ndarray, y: np.ndarray, n: int, rng: int = RANDOM_STATE
) -> Tuple[np.ndarray, np.ndarray]:
    """Return a stratified subset of at most *n* samples."""
    n = min(n, len(y))
    if n == len(y):
        return X, y
    sss = StratifiedShuffleSplit(n_splits=1, test_size=n, random_state=rng)
    _, idx = next(sss.split(X, y))
    return X[idx], y[idx]


def _load_art_classifier(model_name: str) -> Tuple[SklearnClassifier, np.ndarray, np.ndarray]:
    """Load a saved sklearn model + saved test split, wrapped in ART."""
    cfg = MODELS_CONFIG[model_name]
    clf = joblib.load(cfg["model_path"])
    X   = np.load(cfg["X_path"]).astype(np.float32)
    y   = np.load(cfg["y_path"]).astype(np.int64)
    return SklearnClassifier(model=clf, clip_values=(CLIP_MIN, CLIP_MAX)), X, y


def _load_train_data(model_name: str) -> Tuple[np.ndarray, np.ndarray]:
    """
    Re-load the training split for a model using the same loader + random seed
    as train_models.py, so the data is byte-for-byte identical.
    Returns (X_train, y_train) in the same feature space as the saved test arrays.
    """
    cfg         = MODELS_CONFIG[model_name]
    loader_name = cfg["loader"]

    if loader_name == "ember":
        from loaders.ember_loader import load_ember_data
        X_full, y_full = load_ember_data(RANDOM_STATE)
    elif loader_name == "nslkdd":
        from loaders.nslkdd_loader import load_nslkdd_data
        X_full, y_full = load_nslkdd_data(RANDOM_STATE)
    elif loader_name == "phishing":
        from loaders.phishing_loader import load_phishing_data
        X_full, y_full = load_phishing_data(RANDOM_STATE)
    else:
        raise ValueError(f"Unknown loader: {loader_name}")

    X_train, _, y_train, _ = train_test_split(
        X_full, y_full, test_size=0.2, random_state=RANDOM_STATE, stratify=y_full
    )
    X_train = X_train.astype(np.float32)

    # Apply scaler if the model used one (phishing only)
    scaler_path = cfg.get("scaler_path")
    if scaler_path and os.path.exists(scaler_path):
        scaler  = joblib.load(scaler_path)
        X_train = scaler.transform(X_train).astype(np.float32)

    return X_train, y_train.astype(np.int64)


def _build_surrogate(model_name: str, X_train: np.ndarray, y_train: np.ndarray) -> SklearnClassifier:
    """
    Train a lightweight gradient-capable surrogate (SGDClassifier with
    'modified_huber' loss — produces probability outputs compatible with ART).

    Gradient-based attacks (FGSM, C&W, DeepFool) run against this surrogate;
    adversarial examples are then transferred to and evaluated on the original model.
    This is the realistic threat model for black-box/grey-box scenarios.
    """
    surrogate = SGDClassifier(
        loss="modified_huber",
        max_iter=1000,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    surrogate.fit(X_train, y_train)
    log.info("    Surrogate SGD accuracy: %.4f", surrogate.score(X_train, y_train))
    return SklearnClassifier(model=surrogate, clip_values=(CLIP_MIN, CLIP_MAX))


def _compute_metrics(
    art_clf: SklearnClassifier,
    X_clean: np.ndarray,
    y_true:  np.ndarray,
    X_adv:   np.ndarray,
    n_queries: Optional[int] = None,
    **extra,
) -> Dict:
    """Compute the 4 core benchmark metrics (+ optional query count + extras)."""
    prob_clean = art_clf.predict(X_clean)
    prob_adv   = art_clf.predict(X_adv)

    y_pred_clean = np.argmax(prob_clean, axis=1)
    y_pred_adv   = np.argmax(prob_adv,   axis=1)

    original_accuracy    = float(accuracy_score(y_true, y_pred_clean))
    post_attack_accuracy = float(accuracy_score(y_true, y_pred_adv))

    malicious_mask = y_true == 1
    correct_mal    = (y_pred_clean == 1) & malicious_mask
    evasion_rate   = float(
        ((y_pred_adv == 0) & correct_mal).sum() / correct_mal.sum()
    ) if correct_mal.sum() > 0 else 0.0

    idx              = np.arange(len(y_true))
    confidence_delta = float(np.mean(prob_clean[idx, y_true] - prob_adv[idx, y_true]))

    result: Dict = {
        "original_accuracy":    round(original_accuracy,    4),
        "post_attack_accuracy": round(post_attack_accuracy, 4),
        "evasion_rate":         round(evasion_rate,         4),
        "confidence_delta":     round(confidence_delta,     4),
    }
    if n_queries is not None:
        result["n_queries"] = int(n_queries)
    result.update(extra)
    return result


def _estimate_queries(attack_name: str, n_samples: int, n_features: int) -> int:
    """
    Estimate the total number of model forward passes an attack will make.
    Used for query budget display and rate-limiting analysis.
    """
    if attack_name == "fgsm":
        return n_samples                                   # 1 forward + 1 backward per sample
    if attack_name == "hopskipjump":
        return n_samples * (10 + 10 * 50)                 # init_eval + max_iter × max_eval
    if attack_name == "zoo":
        return n_samples * 10 * (2 * min(n_features, 128) + 1)   # coordinate-wise finite-diff
    if attack_name == "cw":
        return n_samples * 5 * 10                         # binary_search_steps × max_iter
    if attack_name == "deepfool":
        return n_samples * 50                             # max_iter per sample
    return n_samples


def _append_history(params: dict, results: dict) -> None:
    """Append a completed benchmark run summary to run_history.json (keeps last 30)."""
    try:
        history: List[dict] = []
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE) as fh:
                history = json.load(fh)

        all_er = [
            results.get(m, {}).get(a, {}).get("evasion_rate")
            for m in MODELS_CONFIG
            for a in VALID_ATTACKS
            if isinstance(results.get(m, {}).get(a), dict)
            and "error" not in results.get(m, {}).get(a, {})
        ]
        all_er = [e for e in all_er if e is not None]

        history.append({
            "timestamp":   datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "params":      params,
            "max_evasion": round(max(all_er), 4) if all_er else 0.0,
            "avg_evasion": round(sum(all_er) / len(all_er), 4) if all_er else 0.0,
            "n_results":   len(all_er),
        })
        history = history[-30:]

        with open(HISTORY_FILE, "w") as fh:
            json.dump(history, fh, indent=2)
    except Exception as exc:
        log.warning("History append failed: %s", exc)


# ---------------------------------------------------------------------------
# Attack wrappers
# ---------------------------------------------------------------------------

def _run_fgsm(surrogate: SklearnClassifier, X: np.ndarray, eps: float = 0.05) -> np.ndarray:
    """
    FGSM against the surrogate SGDClassifier (transfer attack).
    Always uses the surrogate — ensures gradient availability regardless of
    the original model type (RandomForest, GradientBoosting, etc.)
    """
    attack = FastGradientMethod(estimator=surrogate, eps=eps, eps_step=eps / 4)
    return attack.generate(x=X)


def _run_hopskipjump(art_clf: SklearnClassifier, X: np.ndarray) -> np.ndarray:
    """HopSkipJump — black-box boundary attack (label-only access)."""
    attack = HopSkipJump(
        classifier=art_clf,
        targeted=False,
        max_iter=10,
        max_eval=50,
        init_eval=10,
        verbose=False,
    )
    return attack.generate(x=X)


def _run_zoo(art_clf: SklearnClassifier, X: np.ndarray) -> np.ndarray:
    """ZooAttack — black-box zeroth-order optimisation (probability access).
    FIX: batch_size=1 required for feature-vector inputs (was 64 → caused error)."""
    attack = ZooAttack(
        classifier=art_clf,
        confidence=0.0,
        targeted=False,
        learning_rate=1e-1,
        max_iter=10,
        binary_search_steps=1,
        initial_const=1e-3,
        abort_early=True,
        use_resize=False,
        use_importance=False,
        nb_parallel=1,
        batch_size=1,       # FIX: feature vectors require batch_size=1
        variable_h=0.2,
        verbose=False,
    )
    return attack.generate(x=X)


def _run_cw(surrogate: SklearnClassifier, X: np.ndarray) -> np.ndarray:
    """Carlini & Wagner L2 (minimum-distortion white-box attack via surrogate)."""
    attack = CarliniL2Method(
        classifier=surrogate,
        confidence=0.0,
        targeted=False,
        learning_rate=0.01,
        binary_search_steps=5,
        max_iter=10,
        initial_const=0.01,
        max_halving=5,
        max_doubling=5,
        batch_size=1,
        verbose=False,
    )
    return attack.generate(x=X)


def _run_deepfool(surrogate: SklearnClassifier, X: np.ndarray) -> np.ndarray:
    """DeepFool — minimal perturbation boundary-seeking attack via surrogate."""
    attack = DeepFool(
        classifier=surrogate,
        max_iter=50,
        epsilon=1e-6,
        nb_grads=10,
        batch_size=1,
        verbose=False,
    )
    return attack.generate(x=X)


# ---------------------------------------------------------------------------
# Public API — run_benchmark
# ---------------------------------------------------------------------------

def run_benchmark(
    model_name:         str   = "all",
    attack_name:        str   = "all",
    eps:                float = 0.05,
    use_constraints:    bool  = False,
    n_samples_override: Optional[int] = None,
) -> Dict:
    """
    Run adversarial benchmarks and write results/benchmark_results.json.

    Parameters
    ----------
    model_name         : "all" | "malware" | "ids" | "phishing"
    attack_name        : "all" | "fgsm" | "hopskipjump" | "zoo" | "cw" | "deepfool"
    eps                : Perturbation budget for FGSM and C&W
    use_constraints    : If True, apply domain-realistic feature masks post-generation
    n_samples_override : Override default sample sizes for all attacks
    """
    os.makedirs(RESULTS_DIR, exist_ok=True)

    existing: Dict = {}
    if os.path.exists(RESULTS_FILE):
        with open(RESULTS_FILE) as fh:
            existing = json.load(fh)

    models  = list(MODELS_CONFIG.keys()) if model_name == "all" else [model_name]
    attacks = (
        [a for a in _ATTACK_ORDER]
        if attack_name == "all"
        else [attack_name]
    )

    combinations = [(m, a) for m in models for a in attacks]
    total        = len(combinations)
    start_time   = time.time()

    _write_progress({
        "status": "starting", "total": total, "done": 0,
        "current_label": "Initialising…", "started_at": start_time,
        "elapsed_s": 0, "eta_s": None,
    })

    results: Dict = dict(existing)
    done    = 0

    for m in models:
        results.setdefault(m, {})
        cfg     = MODELS_CONFIG[m]
        missing = [p for p in [cfg["model_path"], cfg["X_path"], cfg["y_path"]]
                   if not os.path.exists(p)]
        if missing:
            log.error("Missing model files for '%s': %s. Run train_models.py first.", m, missing)
            results[m]["_error"] = f"Missing: {missing}"
            done += len(attacks)
            continue

        try:
            art_clf, X_all, y_all = _load_art_classifier(m)
        except Exception as exc:
            log.error("Failed to load model '%s': %s", m, exc)
            results[m]["_error"] = str(exc)
            done += len(attacks)
            continue

        # Build surrogate once per model (shared across gradient-based attacks)
        surrogate: Optional[SklearnClassifier] = None
        if any(a in _GRADIENT_ATTACKS for a in attacks):
            try:
                log.info("  Building surrogate for '%s' …", m)
                X_tr, y_tr = _load_train_data(m)
                surrogate  = _build_surrogate(m, X_tr, y_tr)
            except Exception as exc:
                log.warning("  Surrogate training failed for '%s': %s", m, exc)

        for a in attacks:
            elapsed = time.time() - start_time
            eta     = round(elapsed / done * (total - done), 1) if done > 0 else None
            label   = f"{a.upper()} on {m}"

            _write_progress({
                "status": "running", "total": total, "done": done,
                "current_label": label, "started_at": start_time,
                "elapsed_s": round(elapsed, 1), "eta_s": eta,
            })
            log.info("→ [%d/%d] %s …%s",
                     done + 1, total, label,
                     f"  ETA ~{eta:.0f}s" if eta is not None else "")

            n = n_samples_override or MODEL_SAMPLE_OVERRIDES.get(m, {}).get(
                a, ATTACK_SAMPLE_SIZES.get(a, 500)
            )
            X_sub, y_sub = _stratified_subset(X_all, y_all, n)
            n_queries    = _estimate_queries(a, len(y_sub), X_sub.shape[1])

            try:
                if a == "fgsm":
                    if surrogate is None:
                        raise RuntimeError("Surrogate unavailable — cannot run FGSM.")
                    X_adv = _run_fgsm(surrogate, X_sub, eps=eps)

                elif a == "hopskipjump":
                    X_adv = _run_hopskipjump(art_clf, X_sub)

                elif a == "zoo":
                    X_adv = _run_zoo(art_clf, X_sub)

                elif a == "cw":
                    if surrogate is None:
                        raise RuntimeError("Surrogate unavailable — cannot run C&W.")
                    X_adv = _run_cw(surrogate, X_sub)

                elif a == "deepfool":
                    if surrogate is None:
                        raise RuntimeError("Surrogate unavailable — cannot run DeepFool.")
                    X_adv = _run_deepfool(surrogate, X_sub)

                else:
                    done += 1
                    continue

                if use_constraints:
                    from loaders.feature_constraints import apply_constraints
                    X_adv = apply_constraints(m, X_sub, X_adv)

                metrics = _compute_metrics(
                    art_clf, X_sub, y_sub, X_adv,
                    n_queries      = n_queries,
                    model          = m,
                    attack         = a,
                    epsilon        = eps if a in ("fgsm", "cw") else None,
                    n_samples      = int(len(y_sub)),
                    constrained    = use_constraints,
                    via_surrogate  = a in _GRADIENT_ATTACKS,
                )
                results[m][a] = metrics
                log.info("  ✓ evasion=%.1f%%  post_acc=%.4f  est_queries=%d",
                         metrics["evasion_rate"] * 100,
                         metrics["post_attack_accuracy"], n_queries)

            except Exception as exc:
                log.error("Attack '%s' on '%s' failed: %s", a, m, exc)
                results[m][a] = {"model": m, "attack": a, "error": str(exc)}

            done += 1

    total_elapsed = time.time() - start_time
    _write_progress({
        "status": "done", "total": total, "done": total,
        "current_label": "Complete", "started_at": start_time,
        "elapsed_s": round(total_elapsed, 1), "eta_s": 0,
    })

    with open(RESULTS_FILE, "w") as fh:
        json.dump(results, fh, indent=2)
    log.info("✓ All done in %.0fs  →  %s", total_elapsed, RESULTS_FILE)

    _append_history(
        {"model": model_name, "attack": attack_name, "eps": eps,
         "use_constraints": use_constraints},
        results,
    )
    return results


# ---------------------------------------------------------------------------
# Public API — run_epsilon_sweep
# ---------------------------------------------------------------------------

def run_epsilon_sweep(
    model_name:  str             = "malware",
    attack_name: str             = "fgsm",
    eps_values:  Optional[List[float]] = None,
) -> Dict:
    """
    Run a gradient-based attack across multiple epsilon values.
    Returns evasion_rate and post-attack accuracy curves per model for plotting.

    Parameters
    ----------
    model_name  : "all" | "malware" | "ids" | "phishing"
    attack_name : attack to sweep (fgsm recommended; others ignore eps)
    eps_values  : list of epsilon values to test
    """
    if eps_values is None:
        eps_values = [0.01, 0.05, 0.1, 0.2, 0.3, 0.5]

    os.makedirs(RESULTS_DIR, exist_ok=True)
    models = list(MODELS_CONFIG.keys()) if model_name == "all" else [model_name]

    sweep: Dict = {"eps_values": eps_values, "attack": attack_name, "curves": {}}

    for m in models:
        if not os.path.exists(MODELS_CONFIG[m]["model_path"]):
            log.warning("Model '%s' not found, skipping sweep.", m)
            continue

        try:
            art_clf, X_all, y_all = _load_art_classifier(m)
        except Exception as exc:
            log.error("Failed to load '%s' for sweep: %s", m, exc)
            continue

        surrogate: Optional[SklearnClassifier] = None
        if attack_name in _GRADIENT_ATTACKS:
            try:
                X_tr, y_tr = _load_train_data(m)
                surrogate  = _build_surrogate(m, X_tr, y_tr)
            except Exception as exc:
                log.warning("Surrogate failed for sweep '%s': %s", m, exc)

        # Cap sample count for speed during sweep
        n_base = MODEL_SAMPLE_OVERRIDES.get(m, {}).get(
            attack_name, ATTACK_SAMPLE_SIZES.get(attack_name, 200)
        )
        n = min(n_base, 150)
        X_sub, y_sub = _stratified_subset(X_all, y_all, n)

        evasion_rates, post_accs = [], []

        for eps in eps_values:
            try:
                if attack_name == "fgsm":
                    if surrogate is None:
                        raise RuntimeError("No surrogate")
                    X_adv = _run_fgsm(surrogate, X_sub, eps=eps)
                elif attack_name == "cw":
                    if surrogate is None:
                        raise RuntimeError("No surrogate")
                    X_adv = _run_cw(surrogate, X_sub)
                elif attack_name == "hopskipjump":
                    X_adv = _run_hopskipjump(art_clf, X_sub)
                elif attack_name == "zoo":
                    X_adv = _run_zoo(art_clf, X_sub)
                elif attack_name == "deepfool":
                    if surrogate is None:
                        raise RuntimeError("No surrogate")
                    X_adv = _run_deepfool(surrogate, X_sub)
                else:
                    evasion_rates.append(None)
                    post_accs.append(None)
                    continue

                mt = _compute_metrics(art_clf, X_sub, y_sub, X_adv)
                evasion_rates.append(round(mt["evasion_rate"] * 100, 2))
                post_accs.append(round(mt["post_attack_accuracy"] * 100, 2))
                log.info("  Sweep %s+%s eps=%.3f → evasion=%.1f%%",
                         m, attack_name, eps, evasion_rates[-1])

            except Exception as exc:
                log.warning("  Sweep eps=%.3f failed: %s", eps, exc)
                evasion_rates.append(None)
                post_accs.append(None)

        sweep["curves"][m] = {
            "evasion_rates":  evasion_rates,
            "post_accuracies": post_accs,
        }

    sweep_file = os.path.join(RESULTS_DIR, "sweep_results.json")
    with open(sweep_file, "w") as fh:
        json.dump(sweep, fh, indent=2)

    return sweep


# ---------------------------------------------------------------------------
# Public API — apply_defense (adversarial training)
# ---------------------------------------------------------------------------

def apply_defense(
    model_name:    str   = "malware",
    attack_name:   str   = "fgsm",
    eps:           float = 0.05,
    augment_ratio: float = 0.3,
) -> Dict:
    """
    Apply adversarial training (the most effective known defence against AML attacks).

    Steps
    -----
    1. Load original trained model + its training data
    2. Generate adversarial examples from augment_ratio × n_train samples
    3. Concatenate clean + adversarial training examples
    4. Clone and retrain the model on the augmented dataset
    5. Generate adversarial examples from the test set
    6. Evaluate both original and defended models on the same adversarial test set
    7. Return before/after comparison and save to results/defense_results.json

    Parameters
    ----------
    model_name    : "malware" | "ids" | "phishing"
    attack_name   : attack used to craft adversarial training examples
    eps           : perturbation budget (for FGSM / C&W)
    augment_ratio : fraction of training data to augment with adversarial examples
    """
    cfg = MODELS_CONFIG.get(model_name)
    if cfg is None or not os.path.exists(cfg["model_path"]):
        return {"error": f"Model '{model_name}' not found. Run train_models.py first."}

    log.info("=== Adversarial Training: %s ← %s (ratio=%.0f%%) ===",
             model_name, attack_name, augment_ratio * 100)

    # ── Load original model and test data ───────────────────────────────────
    try:
        art_clf, X_test, y_test = _load_art_classifier(model_name)
        original_clf = art_clf._model
    except Exception as exc:
        return {"error": f"Failed to load model: {exc}"}

    # ── Load training data ───────────────────────────────────────────────────
    try:
        X_train, y_train = _load_train_data(model_name)
    except Exception as exc:
        return {"error": f"Failed to load training data: {exc}"}

    # ── Build surrogate ──────────────────────────────────────────────────────
    surrogate: Optional[SklearnClassifier] = None
    if attack_name in _GRADIENT_ATTACKS:
        try:
            surrogate = _build_surrogate(model_name, X_train, y_train)
        except Exception as exc:
            return {"error": f"Surrogate training failed: {exc}"}

    # ── Generate adversarial training examples ───────────────────────────────
    n_adv = min(int(len(X_train) * augment_ratio), 500)
    X_adv_src, y_adv_src = _stratified_subset(X_train, y_train, n_adv)

    log.info("  Generating %d adversarial training examples …", n_adv)
    try:
        if attack_name == "fgsm":
            X_adv_aug = _run_fgsm(surrogate, X_adv_src, eps=eps)
        elif attack_name == "hopskipjump":
            X_adv_aug = _run_hopskipjump(art_clf, X_adv_src)
        elif attack_name == "zoo":
            X_adv_aug = _run_zoo(art_clf, X_adv_src)
        elif attack_name == "cw":
            X_adv_aug = _run_cw(surrogate, X_adv_src)
        elif attack_name == "deepfool":
            X_adv_aug = _run_deepfool(surrogate, X_adv_src)
        else:
            X_adv_aug = _run_fgsm(surrogate, X_adv_src, eps=eps) if surrogate else X_adv_src
    except Exception as exc:
        return {"error": f"Adversarial example generation failed: {exc}"}

    # ── Augment training data + retrain ──────────────────────────────────────
    X_aug = np.concatenate([X_train, X_adv_aug])
    y_aug = np.concatenate([y_train, y_adv_src])

    log.info("  Retraining %s on augmented set (%d → %d samples) …",
             type(original_clf).__name__, len(X_train), len(X_aug))
    try:
        defended_clf = clone(original_clf)
        defended_clf.fit(X_aug, y_aug)
    except Exception as exc:
        return {"error": f"Retraining failed: {exc}"}

    defended_art = SklearnClassifier(model=defended_clf, clip_values=(CLIP_MIN, CLIP_MAX))

    # ── Generate adversarial TEST examples ───────────────────────────────────
    n_test = min(
        MODEL_SAMPLE_OVERRIDES.get(model_name, {}).get(
            attack_name, ATTACK_SAMPLE_SIZES.get(attack_name, 200)
        ),
        200,
    )
    X_te_sub, y_te_sub = _stratified_subset(X_test, y_test, n_test)

    log.info("  Evaluating before/after on %d adversarial test samples …", n_test)
    try:
        if attack_name == "fgsm":
            X_te_adv = _run_fgsm(surrogate, X_te_sub, eps=eps)
        elif attack_name == "hopskipjump":
            X_te_adv = _run_hopskipjump(art_clf, X_te_sub)
        elif attack_name == "zoo":
            X_te_adv = _run_zoo(art_clf, X_te_sub)
        elif attack_name == "cw":
            X_te_adv = _run_cw(surrogate, X_te_sub)
        elif attack_name == "deepfool":
            X_te_adv = _run_deepfool(surrogate, X_te_sub)
        else:
            X_te_adv = _run_fgsm(surrogate, X_te_sub, eps=eps) if surrogate else X_te_sub
    except Exception as exc:
        return {"error": f"Test adversarial generation failed: {exc}"}

    before = _compute_metrics(art_clf,     X_te_sub, y_te_sub, X_te_adv)
    after  = _compute_metrics(defended_art, X_te_sub, y_te_sub, X_te_adv)
    improvement = round(before["evasion_rate"] - after["evasion_rate"], 4)

    result = {
        "model":         model_name,
        "attack":        attack_name,
        "eps":           eps,
        "augment_ratio": augment_ratio,
        "n_adv_samples": n_adv,
        "before":        before,
        "after":         after,
        "improvement":   improvement,
        "timestamp":     datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }

    # Persist
    existing_defense: Dict = {}
    if os.path.exists(DEFENSE_FILE):
        with open(DEFENSE_FILE) as fh:
            existing_defense = json.load(fh)
    existing_defense.setdefault(model_name, {})[attack_name] = result

    with open(DEFENSE_FILE, "w") as fh:
        json.dump(existing_defense, fh, indent=2)

    log.info("  ✓ Defense: evasion %.1f%% → %.1f%%  (Δ=%.1f%%)",
             before["evasion_rate"] * 100,
             after["evasion_rate"]  * 100,
             improvement * 100)
    return result


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Adversarial ML Attack Runner v2")
    parser.add_argument("--model",  default="all",
                        choices=["all", "malware", "ids", "phishing"])
    parser.add_argument("--attack", default="all",
                        choices=["all", "fgsm", "hopskipjump", "zoo", "cw", "deepfool"])
    parser.add_argument("--eps",      type=float, default=0.05,
                        help="Perturbation budget for FGSM/C&W (default: 0.05)")
    parser.add_argument("--constrain", action="store_true",
                        help="Apply domain-realistic feature constraints post-generation")
    parser.add_argument("--sweep",   action="store_true",
                        help="Run epsilon sweep instead of single benchmark")
    parser.add_argument("--defend",  action="store_true",
                        help="Apply adversarial training defense")
    parser.add_argument("--ratio",   type=float, default=0.3,
                        help="Augmentation ratio for adversarial training (default: 0.3)")
    args = parser.parse_args()

    if args.sweep:
        out = run_epsilon_sweep(model_name=args.model, attack_name=args.attack)
    elif args.defend:
        m = args.model if args.model != "all" else "malware"
        a = args.attack if args.attack != "all" else "fgsm"
        out = apply_defense(model_name=m, attack_name=a, eps=args.eps, augment_ratio=args.ratio)
    else:
        out = run_benchmark(
            model_name=args.model, attack_name=args.attack,
            eps=args.eps, use_constraints=args.constrain,
        )

    import pprint
    pprint.pprint(out)
