"""
tests/test_attack_runner.py — Unit tests for the attack_runner module.

Tests use small synthetic datasets so no pre-trained model files are needed
for the pure-logic tests.  Tests that require ART are skipped if the package
is not installed (graceful CI degradation).

Run with:
    pytest tests/test_attack_runner.py -v
"""

import json
import os
import sys
import tempfile
import types

import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression

# ---------------------------------------------------------------------------
# Helper — build a tiny fitted classifier wrapped in ART's SklearnClassifier
# ---------------------------------------------------------------------------

def _make_tiny_dataset(n=200, n_features=10, seed=42):
    rng = np.random.default_rng(seed)
    X = rng.standard_normal((n, n_features)).astype(np.float32)
    y = rng.integers(0, 2, size=n)
    return X, y


def _make_art_classifier(clf, X, y):
    """Fit *clf* on (X, y) and wrap in ART SklearnClassifier."""
    from art.estimators.classification import SklearnClassifier
    clf.fit(X, y)
    return SklearnClassifier(model=clf, clip_values=(-10.0, 10.0))


# ---------------------------------------------------------------------------
# Test 1 — _stratified_subset returns correct size and dtype
# ---------------------------------------------------------------------------

def test_stratified_subset_size():
    """_stratified_subset must return exactly *n* samples."""
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from attack_runner import _stratified_subset

    X, y = _make_tiny_dataset(200)
    X_sub, y_sub = _stratified_subset(X, y, 50)
    assert len(X_sub) == 50
    assert len(y_sub) == 50
    assert X_sub.dtype == np.float32


def test_stratified_subset_no_truncate():
    """If n >= len(y), all samples are returned unchanged."""
    from attack_runner import _stratified_subset

    X, y = _make_tiny_dataset(100)
    X_sub, y_sub = _stratified_subset(X, y, 200)   # request more than available
    assert len(X_sub) == 100


# ---------------------------------------------------------------------------
# Test 2 — _compute_metrics returns expected keys and value ranges
# ---------------------------------------------------------------------------

def test_compute_metrics_keys_and_ranges():
    """_compute_metrics must return all 4 required metric keys with valid ranges."""
    pytest.importorskip("art", reason="ART not installed")
    from attack_runner import _compute_metrics

    X, y = _make_tiny_dataset(100)
    clf = LogisticRegression(max_iter=200, random_state=42)
    art_clf = _make_art_classifier(clf, X, y)

    # Use the clean data as both clean and "adversarial" (no actual attack)
    metrics = _compute_metrics(art_clf, X, y, X)

    required_keys = {"original_accuracy", "post_attack_accuracy",
                     "evasion_rate", "confidence_delta"}
    assert required_keys.issubset(metrics.keys()), \
        f"Missing keys: {required_keys - metrics.keys()}"

    assert 0.0 <= metrics["original_accuracy"]   <= 1.0
    assert 0.0 <= metrics["post_attack_accuracy"] <= 1.0
    assert 0.0 <= metrics["evasion_rate"]          <= 1.0
    # confidence_delta can be negative if model becomes more confident after noise
    assert isinstance(metrics["confidence_delta"], float)


# ---------------------------------------------------------------------------
# Test 3 — FGSM generates adversarial examples with non-zero perturbation
# ---------------------------------------------------------------------------

def test_fgsm_generates_perturbation():
    """FGSM X_adv must differ from X_clean (perturbation > 0)."""
    pytest.importorskip("art", reason="ART not installed")
    from attack_runner import _run_fgsm

    X, y = _make_tiny_dataset(50)
    clf = LogisticRegression(max_iter=200, random_state=42)
    art_clf = _make_art_classifier(clf, X, y)

    X_adv = _run_fgsm(art_clf, X, eps=0.05)

    assert X_adv.shape == X.shape, "Adversarial shape must match clean shape"
    diff = np.abs(X_adv - X).max()
    assert diff > 0, "FGSM produced no perturbation"
    # Perturbation should be bounded by eps (with small float tolerance)
    assert diff <= 0.05 + 1e-5, f"Max perturbation {diff:.6f} exceeds eps=0.05"


# ---------------------------------------------------------------------------
# Test 4 — results JSON is valid after a benchmark run
# ---------------------------------------------------------------------------

def test_benchmark_results_json_valid(tmp_path, monkeypatch):
    """run_benchmark must write a valid JSON file to RESULTS_DIR."""
    pytest.importorskip("art", reason="ART not installed")

    # Patch paths to use tmp_path
    import attack_runner as ar
    monkeypatch.setattr(ar, "RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(ar, "RESULTS_FILE", str(tmp_path / "benchmark_results.json"))
    monkeypatch.setattr(ar, "MODELS_DIR", str(tmp_path / "models"))
    os.makedirs(tmp_path / "models", exist_ok=True)

    # Build and save a tiny model + test split
    import joblib
    from art.estimators.classification import SklearnClassifier
    X, y = _make_tiny_dataset(100)
    clf = LogisticRegression(max_iter=200, random_state=42)
    clf.fit(X, y)
    joblib.dump(clf, tmp_path / "models" / "malware_classifier.pkl")
    np.save(tmp_path / "models" / "malware_classifier_test_X.npy", X.astype(np.float32))
    np.save(tmp_path / "models" / "malware_classifier_test_y.npy", y.astype(np.int64))

    # Update config to point to tmp_path
    original_cfg = ar.MODELS_CONFIG.copy()
    ar.MODELS_CONFIG["malware"] = {
        "model_path": str(tmp_path / "models" / "malware_classifier.pkl"),
        "X_path":     str(tmp_path / "models" / "malware_classifier_test_X.npy"),
        "y_path":     str(tmp_path / "models" / "malware_classifier_test_y.npy"),
    }

    try:
        results = ar.run_benchmark(model_name="malware", attack_name="fgsm", eps=0.05)
    finally:
        ar.MODELS_CONFIG.update(original_cfg)

    results_file = tmp_path / "benchmark_results.json"
    assert results_file.exists(), "benchmark_results.json was not created"

    with open(results_file) as fh:
        loaded = json.load(fh)

    assert "malware" in loaded
    assert "fgsm" in loaded["malware"]


# ---------------------------------------------------------------------------
# Test 5 — report_generator returns error dict when API key is missing
# ---------------------------------------------------------------------------

def test_report_generator_missing_api_key(monkeypatch):
    """generate_report must return a dict with 'error' if ANTHROPIC_API_KEY is absent."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    from report_generator import generate_report

    # Provide dummy results so the function doesn't fail on missing file
    dummy_results = {
        "malware": {
            "fgsm": {
                "original_accuracy": 0.92,
                "post_attack_accuracy": 0.60,
                "evasion_rate": 0.45,
                "confidence_delta": 0.32,
            }
        }
    }
    result = generate_report(results=dummy_results)
    assert isinstance(result, dict)
    assert "error" in result
    assert "ANTHROPIC_API_KEY" in result["error"]


# ---------------------------------------------------------------------------
# Test 6 — loader returns correct shapes
# ---------------------------------------------------------------------------

def test_loaders_output_shapes():
    """All three loaders must return (X, y) with expected feature counts."""
    from loaders.ember_loader    import load_ember_data,    N_FEATURES as NF_EMBER
    from loaders.nslkdd_loader   import load_nslkdd_data,   N_FEATURES as NF_KDD
    from loaders.phishing_loader import load_phishing_data, N_FEATURES as NF_PHISH

    for loader, expected_features in [
        (load_ember_data,    NF_EMBER),
        (load_nslkdd_data,   NF_KDD),
        (load_phishing_data, NF_PHISH),
    ]:
        X, y = loader(random_state=42)
        assert X.ndim == 2
        assert X.shape[1] == expected_features, \
            f"{loader.__module__}: expected {expected_features} features, got {X.shape[1]}"
        assert len(X) == len(y)
        assert set(np.unique(y)).issubset({0, 1})
