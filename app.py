"""
app.py — Flask application factory for the unified Security Research Labs.

Endpoints:
  GET  /                     — landing page: choose ART Lab or Malware Lab
  GET  /art                  — ART Lab dashboard (templates/dashboard.html)
  GET  /malware              — Malware Analysis Lab (templates/malware_lab.html)
  GET  /report               — rendered AI threat-analysis report page
  GET  /api/results          — return benchmark_results.json
  POST /api/run-benchmark    — run specific or all benchmarks
                               body: {model, attack, epsilon}
  GET  /api/generate-report  — generate AI threat report via Claude Haiku,
                               saves last_report.json and returns redirect URL

All endpoints return JSON for errors; HTML pages are / and /report.

New in v2:
  GET  /api/profiles        — return ATTACK_PROFILES catalogue
  POST /api/epsilon-sweep   — evasion-rate vs epsilon curve
                               body: {model, attack, eps_values}
  POST /api/defend          — apply adversarial training defense
                               body: {model, attack, eps, augment_ratio}
  GET  /api/defense-results — return defense_results.json
  GET  /api/history         — return run_history.json
  GET  /api/sessions        — list all saved sessions (metadata only)
  GET  /api/sessions/<id>   — load full results for a specific session
"""

import os
import re
import json
import logging
import secrets
from datetime import datetime, timezone

import warnings
# ART always tries to import PyTorch certification modules at startup and
# emits a UserWarning when PyTorch isn't installed.  We don't use those
# modules, so silence the noise before ART is imported anywhere.
warnings.filterwarnings("ignore", message="PyTorch not found")

from flask import Flask, render_template, jsonify, request, redirect
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger(__name__)

RESULTS_PATH  = os.path.join("results", "benchmark_results.json")
PROGRESS_PATH = os.path.join("results", "progress.json")
REPORT_PATH   = os.path.join("results", "last_report.json")

_MODEL_KEYS   = ["malware", "ids", "phishing"]
_ATTACK_KEYS  = ["fgsm", "hopskipjump", "zoo", "cw", "deepfool"]
_MODEL_LABELS = {
    "malware":  "Malware Classifier",
    "ids":      "IDS Classifier",
    "phishing": "Phishing Classifier",
}
_ATTACK_LABELS = {
    "fgsm":        "FGSM",
    "hopskipjump": "HopSkipJump",
    "zoo":         "ZooAttack",
    "cw":          "C&W L2",
    "deepfool":    "DeepFool",
}

DEFENSE_PATH  = os.path.join("results", "defense_results.json")
HISTORY_PATH  = os.path.join("results", "run_history.json")
SWEEP_PATH    = os.path.join("results", "sweep_results.json")
SESSIONS_DIR  = os.path.join("results", "sessions")


# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------

def _generate_session_id() -> str:
    """Return an 8-character hex session ID (e.g. 'a3f2b1c9')."""
    return secrets.token_hex(4)


def _create_empty_session() -> str:
    """
    Create a new empty session file immediately (no results yet).
    Returns the session ID so the frontend can show the code right away.
    """
    os.makedirs(SESSIONS_DIR, exist_ok=True)
    sid = _generate_session_id()
    session = {
        "session_id":  sid,
        "created_at":  datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "params":      {},
        "max_evasion": None,
        "avg_evasion": None,
        "n_results":   0,
        "results":     {},
    }
    path = os.path.join(SESSIONS_DIR, f"{sid}.json")
    with open(path, "w") as fh:
        json.dump(session, fh, indent=2)
    log.info("Empty session created → %s", path)
    return sid


def _update_session(sid: str, params: dict, results: dict) -> str:
    """
    Write benchmark results into an existing session (or create one if missing).
    Returns the session ID.
    """
    os.makedirs(SESSIONS_DIR, exist_ok=True)
    path = os.path.join(SESSIONS_DIR, f"{sid}.json")

    # Load existing metadata so we preserve created_at
    existing: dict = {}
    if os.path.exists(path):
        try:
            with open(path) as fh:
                existing = json.load(fh)
        except Exception:
            pass

    # Compute evasion stats
    all_er = [
        results.get(m, {}).get(a, {}).get("evasion_rate")
        for m in _MODEL_KEYS
        for a in _ATTACK_KEYS
        if isinstance(results.get(m, {}).get(a), dict)
        and "error" not in results.get(m, {}).get(a, {})
    ]
    all_er = [e for e in all_er if e is not None]

    existing.update({
        "session_id":  sid,
        "created_at":  existing.get("created_at",
                       datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")),
        "params":      params,
        "max_evasion": round(max(all_er), 4) if all_er else 0.0,
        "avg_evasion": round(sum(all_er) / len(all_er), 4) if all_er else 0.0,
        "n_results":   len(all_er),
        "results":     results,
    })

    with open(path, "w") as fh:
        json.dump(existing, fh, indent=2)
    log.info("Session updated → %s", path)
    return sid


def _list_sessions() -> list:
    """Return metadata for all saved sessions, newest first."""
    if not os.path.isdir(SESSIONS_DIR):
        return []
    sessions = []
    for fname in os.listdir(SESSIONS_DIR):
        if not fname.endswith(".json"):
            continue
        try:
            with open(os.path.join(SESSIONS_DIR, fname)) as fh:
                data = json.load(fh)
            # Return only lightweight metadata (exclude full results)
            sessions.append({
                "session_id":  data.get("session_id", fname[:-5]),
                "created_at":  data.get("created_at", ""),
                "params":      data.get("params", {}),
                "max_evasion": data.get("max_evasion", 0.0),
                "avg_evasion": data.get("avg_evasion", 0.0),
                "n_results":   data.get("n_results", 0),
            })
        except Exception:
            pass
    sessions.sort(key=lambda s: s.get("created_at", ""), reverse=True)
    return sessions


# ---------------------------------------------------------------------------
# Proof-of-Concept code templates (rendered in /report)
# ---------------------------------------------------------------------------

def _highlight_python(code: str) -> str:
    """Return HTML for a Python snippet with basic comment/import colouring."""
    import html as _h
    lines = []
    for line in code.split("\n"):
        esc      = _h.escape(line)
        stripped = line.strip()
        if stripped.startswith("#"):
            lines.append(f'<span class="code-comment">{esc}</span>')
        elif stripped.startswith(("import ", "from ")):
            lines.append(f'<span class="code-import">{esc}</span>')
        elif stripped.startswith("print("):
            lines.append(f'<span class="code-print">{esc}</span>')
        else:
            lines.append(esc)
    return "\n".join(lines)


# Template variables: {loader_mod} {loader_fn} {model_file} {n_samples} {eps}
# Use {{ }} for literal braces that appear inside Python f-strings in the snippet.
_POC_TEMPLATES = {

"fgsm": """\
# ── FGSM: Fast Gradient Sign Method  (White-box Transfer Attack) ─────────
# How it works: perturbs each feature by  eps × sign(∇ loss)  to maximise
#   the model's misclassification loss in a single step.
# Why surrogate: sklearn RandomForest / GradientBoosting have no gradients,
#   so we train a lightweight SGDClassifier on the same data and transfer
#   the adversarial examples across to the real target model.

import numpy as np, joblib
from sklearn.linear_model import SGDClassifier
from sklearn.model_selection import train_test_split
from art.estimators.classification import SklearnClassifier
from art.attacks.evasion import FastGradientMethod
from {loader_mod} import {loader_fn}

# 1. Load the target model and reproduce the same train/test split
model  = joblib.load("{model_file}")
X, y   = {loader_fn}()
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
X_sample, y_sample = X_test[:{n_samples}], y_test[:{n_samples}]

# 2. Train a gradient-capable surrogate on the same training data
surrogate = SGDClassifier(loss="modified_huber", max_iter=1000, random_state=42, n_jobs=-1)
surrogate.fit(X_train, y_train)
art_surrogate = SklearnClassifier(model=surrogate, clip_values=(0.0, 1.0))

# 3. Generate adversarial examples via FGSM  (eps = {eps})
attack = FastGradientMethod(estimator=art_surrogate, eps={eps})
X_adv  = attack.generate(x=X_sample)

# 4. Evaluate evasion on the REAL target model (not the surrogate)
y_clean = model.predict(X_sample)
y_adv   = model.predict(X_adv)
print(f"Evasion rate : {{np.mean(y_clean != y_adv):.1%}}")
print(f"Accuracy drop: {{np.mean(y_clean == y_sample):.1%}} -> {{np.mean(y_adv == y_sample):.1%}}")
""",

"hopskipjump": """\
# ── HopSkipJump: Black-box Decision-Boundary Attack ──────────────────────
# How it works: iteratively "hops" toward the model's decision boundary
#   using only hard label queries — no probabilities or gradients needed.
# Threat model: realistic for any attacker querying a cloud prediction API.

import numpy as np, joblib
from sklearn.model_selection import train_test_split
from art.estimators.classification import SklearnClassifier
from art.attacks.evasion import HopSkipJump
from {loader_mod} import {loader_fn}

# 1. Load target model — HopSkipJump works directly on the black-box model
model = joblib.load("{model_file}")
X, y  = {loader_fn}()
_, X_test, _, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
X_sample, y_sample = X_test[:{n_samples}], y_test[:{n_samples}]

# 2. Wrap in ART — only predict() is exposed to the attack (black-box)
art_clf = SklearnClassifier(model=model, clip_values=(0.0, 1.0))

# 3. Run HopSkipJump  (~1 000 label queries per sample)
attack = HopSkipJump(
    classifier = art_clf,
    targeted   = False,    # untargeted: just cause any misclassification
    max_iter   = 50,
    max_eval   = 1000,
    init_eval  = 100,
)
X_adv = attack.generate(x=X_sample)

# 4. Measure evasion
y_clean = model.predict(X_sample)
y_adv   = model.predict(X_adv)
print(f"Evasion rate : {{np.mean(y_clean != y_adv):.1%}}")
print(f"Accuracy drop: {{np.mean(y_clean == y_sample):.1%}} -> {{np.mean(y_adv == y_sample):.1%}}")
""",

"zoo": """\
# ── ZooAttack: Zeroth-Order Optimisation  (Black-box, probability-based) ─
# How it works: estimates gradients via finite differences on soft-probability
#   outputs, then minimises a C&W-style loss — no model internals needed.
# Key fix: batch_size=1 is required for feature vectors (ART default of 64
#   assumes image inputs and crashes on tabular data).

import numpy as np, joblib
from sklearn.model_selection import train_test_split
from art.estimators.classification import SklearnClassifier
from art.attacks.evasion import ZooAttack
from {loader_mod} import {loader_fn}

# 1. Load target model
model = joblib.load("{model_file}")
X, y  = {loader_fn}()
_, X_test, _, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
X_sample, y_sample = X_test[:{n_samples}], y_test[:{n_samples}]

art_clf = SklearnClassifier(model=model, clip_values=(0.0, 1.0))

# 2. Run ZooAttack  (slow but broadly applicable — needs predict_proba)
attack = ZooAttack(
    classifier          = art_clf,
    confidence          = 0.0,
    targeted            = False,
    learning_rate       = 1e-1,
    max_iter            = 100,
    binary_search_steps = 10,
    initial_const       = 1e-3,
    abort_early         = True,
    use_resize          = False,  # must be False for tabular / feature-vector data
    batch_size          = 1,      # CRITICAL: feature vectors require batch_size=1
)
X_adv = attack.generate(x=X_sample)

# 3. Measure evasion
y_clean = model.predict(X_sample)
y_adv   = model.predict(X_adv)
print(f"Evasion rate : {{np.mean(y_clean != y_adv):.1%}}")
print(f"Accuracy drop: {{np.mean(y_clean == y_sample):.1%}} -> {{np.mean(y_adv == y_sample):.1%}}")
""",

"cw": """\
# ── C&W L2: Carlini-Wagner L2 Attack  (White-box Transfer) ───────────────
# How it works: jointly minimises  (L2 distance) + (confidence loss)  via
#   Adam optimisation with a binary search over the regularisation constant.
#   Finds the *minimum norm* adversarial perturbation — harder to detect.
# Why surrogate: sklearn tree models have no gradients; same transfer
#   approach as FGSM is used.

import numpy as np, joblib
from sklearn.linear_model import SGDClassifier
from sklearn.model_selection import train_test_split
from art.estimators.classification import SklearnClassifier
from art.attacks.evasion import CarliniL2Method
from {loader_mod} import {loader_fn}

# 1. Load target model and reproduce split
model  = joblib.load("{model_file}")
X, y   = {loader_fn}()
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
X_sample, y_sample = X_test[:{n_samples}], y_test[:{n_samples}]

# 2. Train surrogate for gradient access
surrogate = SGDClassifier(loss="modified_huber", max_iter=1000, random_state=42, n_jobs=-1)
surrogate.fit(X_train, y_train)
art_surrogate = SklearnClassifier(model=surrogate, clip_values=(0.0, 1.0))

# 3. Run C&W L2  (binary search finds the minimum perturbation that fools the model)
attack = CarliniL2Method(
    classifier          = art_surrogate,
    confidence          = 0.0,
    targeted            = False,
    learning_rate       = 1e-2,
    binary_search_steps = 9,
    max_iter            = 100,
    initial_const       = 1e-3,
    batch_size          = 1,
)
X_adv = attack.generate(x=X_sample)

# 4. Evaluate on the real target model
y_clean = model.predict(X_sample)
y_adv   = model.predict(X_adv)
l2_dist = float(np.mean(np.linalg.norm(X_adv - X_sample, axis=1)))
print(f"Evasion rate : {{np.mean(y_clean != y_adv):.1%}}")
print(f"Avg L2 dist  : {{l2_dist:.4f}}  (smaller = stealthier perturbation)")
print(f"Accuracy drop: {{np.mean(y_clean == y_sample):.1%}} -> {{np.mean(y_adv == y_sample):.1%}}")
""",

"deepfool": """\
# ── DeepFool: Minimum-Perturbation Attack  (White-box Transfer) ──────────
# How it works: iteratively projects each sample across the nearest decision
#   boundary with the smallest possible L2 perturbation — much tighter than
#   FGSM, making the adversarial examples harder to detect statistically.
# Why surrogate: same gradient limitation as FGSM — SGDClassifier proxy used.

import numpy as np, joblib
from sklearn.linear_model import SGDClassifier
from sklearn.model_selection import train_test_split
from art.estimators.classification import SklearnClassifier
from art.attacks.evasion import DeepFool
from {loader_mod} import {loader_fn}

# 1. Load target model and reproduce split
model  = joblib.load("{model_file}")
X, y   = {loader_fn}()
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
X_sample, y_sample = X_test[:{n_samples}], y_test[:{n_samples}]

# 2. Train surrogate for gradient access
surrogate = SGDClassifier(loss="modified_huber", max_iter=1000, random_state=42, n_jobs=-1)
surrogate.fit(X_train, y_train)
art_surrogate = SklearnClassifier(model=surrogate, clip_values=(0.0, 1.0))

# 3. Run DeepFool  (finds the minimum perturbation that crosses the boundary)
attack = DeepFool(
    classifier = art_surrogate,
    max_iter   = 100,
    epsilon    = 1e-6,  # convergence threshold (not a perturbation budget)
    nb_grads   = 10,    # number of classes considered per iteration step
    batch_size = 32,
)
X_adv = attack.generate(x=X_sample)

# 4. Evaluate on the real target model
y_clean = model.predict(X_sample)
y_adv   = model.predict(X_adv)
l2_dist = float(np.mean(np.linalg.norm(X_adv - X_sample, axis=1)))
print(f"Evasion rate  : {{np.mean(y_clean != y_adv):.1%}}")
print(f"Avg L2 dist   : {{l2_dist:.4f}}  (smaller = stealthier)")
print(f"Accuracy drop : {{np.mean(y_clean == y_sample):.1%}} -> {{np.mean(y_adv == y_sample):.1%}}")
""",
}


# ---------------------------------------------------------------------------
# Report helpers
# ---------------------------------------------------------------------------

def _parse_report_sections(text):
    """Split the 4-section report text into a dict keyed by section name.
    Works for both Claude-formatted markdown and the rule-based plain-text output."""
    patterns = [
        (r"(?:#+\s*)?(?:\d+[\.\)]\s+)?EXECUTIVE\s+SUMMARY",          "executive_summary"),
        (r"(?:#+\s*)?(?:\d+[\.\)]\s+)?PER[\s\-]?MODEL\s+VULNERABILITY","vulnerability_analysis"),
        (r"(?:#+\s*)?(?:\d+[\.\)]\s+)?ATTACK\s+EFFECTIVENESS",         "attack_comparison"),
        (r"(?:#+\s*)?(?:\d+[\.\)]\s+)?DEFENSIVE\s+RECOMMENDATIONS",    "recommendations"),
    ]
    splits = []
    for pat, key in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            splits.append((m.start(), key))
    splits.sort()
    sections = {key: "" for _, key in patterns}
    for i, (start, key) in enumerate(splits):
        end = splits[i + 1][0] if i + 1 < len(splits) else len(text)
        sections[key] = text[start:end].strip()
    return sections


def _compute_report_stats(results):
    """Derive all display data needed by report.html from benchmark_results.json."""
    all_er, model_stats, attack_stats = [], {}, {}
    global_max, worst_pair = 0.0, None

    for m in _MODEL_KEYS:
        m_ers = []
        for a in _ATTACK_KEYS:
            entry = (results or {}).get(m, {}).get(a)
            if isinstance(entry, dict) and "evasion_rate" in entry and "error" not in entry:
                er = float(entry["evasion_rate"])
                all_er.append(er)
                m_ers.append((a, er))
                if er > global_max:
                    global_max, worst_pair = er, (m, a, er)
        if m_ers:
            model_stats[m] = {
                "max_er":      max(e for _, e in m_ers),
                "avg_er":      sum(e for _, e in m_ers) / len(m_ers),
                "worst_attack": max(m_ers, key=lambda x: x[1])[0],
            }

    for a in _ATTACK_KEYS:
        a_ers = [
            float((results or {}).get(m, {}).get(a, {}).get("evasion_rate", 0))
            for m in _MODEL_KEYS
            if isinstance((results or {}).get(m, {}).get(a), dict)
            and "evasion_rate" in (results or {}).get(m, {}).get(a, {})
            and "error" not in (results or {}).get(m, {}).get(a, {})
        ]
        if a_ers:
            attack_stats[a] = {"avg_er": sum(a_ers) / len(a_ers), "max_er": max(a_ers)}

    avg_er   = sum(all_er) / len(all_er) if all_er else 0.0
    n_crit   = sum(1 for e in all_er if e > 0.5)
    n_high   = sum(1 for e in all_er if 0.2 < e <= 0.5)
    n_mod    = sum(1 for e in all_er if e <= 0.2)

    if global_max > 0.5:
        risk_level, risk_color, risk_emoji = "CRITICAL", "danger", "🔴"
        plain_risk = "serious vulnerabilities — attackers can reliably bypass detection more than half the time"
        action     = "Immediate adversarial hardening is required before any production deployment."
    elif global_max > 0.2:
        risk_level, risk_color, risk_emoji = "HIGH", "warn", "🟡"
        plain_risk = "notable vulnerabilities — attackers can partially evade detection in several scenarios"
        action     = "Targeted defences should be applied before production deployment."
    else:
        risk_level, risk_color, risk_emoji = "MODERATE", "success", "🟢"
        plain_risk = "relatively low vulnerability — the models show reasonable baseline robustness"
        action     = "Regular re-benchmarking is recommended as the threat landscape evolves."

    # Pre-build table rows so the template stays logic-free
    table_rows = []
    for m in _MODEL_KEYS:
        for a in _ATTACK_KEYS:
            entry = (results or {}).get(m, {}).get(a)
            if not isinstance(entry, dict) or "error" in entry or "evasion_rate" not in entry:
                continue
            er = float(entry["evasion_rate"])
            oa = entry.get("original_accuracy")
            pa = entry.get("post_attack_accuracy")
            cd = entry.get("confidence_delta")
            risk = "CRITICAL" if er > 0.5 else ("HIGH" if er > 0.2 else "MODERATE")
            table_rows.append({
                "model":               _MODEL_LABELS.get(m, m),
                "attack":              _ATTACK_LABELS.get(a, a),
                "original_accuracy":   f"{oa*100:.2f}%" if isinstance(oa, (int, float)) else "—",
                "post_attack_accuracy":f"{pa*100:.2f}%" if isinstance(pa, (int, float)) else "—",
                "evasion_rate":        f"{er*100:.1f}%",
                "confidence_delta":    f"{cd:.4f}"      if isinstance(cd, (int, float)) else "—",
                "n_samples":           entry.get("n_samples", "—"),
                "epsilon":             entry.get("epsilon", "—"),
                "risk":                risk,
                "risk_class":          risk.lower(),
                "risk_emoji":          "🔴" if er > 0.5 else ("🟡" if er > 0.2 else "🟢"),
            })

    # Per-model cards pre-built
    model_cards = []
    for m in _MODEL_KEYS:
        ms = model_stats.get(m)
        if not ms:
            continue
        er = ms["max_er"]
        risk = "CRITICAL" if er > 0.5 else ("HIGH" if er > 0.2 else "MODERATE")
        model_cards.append({
            "key":          m,
            "label":        _MODEL_LABELS.get(m, m),
            "max_er_pct":   f"{er*100:.1f}%",
            "avg_er_pct":   f"{ms['avg_er']*100:.1f}%",
            "worst_attack": _ATTACK_LABELS.get(ms["worst_attack"], ms["worst_attack"]),
            "risk":         risk,
            "risk_class":   risk.lower(),
            "risk_emoji":   "🔴" if er > 0.5 else ("🟡" if er > 0.2 else "🟢"),
        })

    # Per-attack cards pre-built
    attack_cards = []
    _attack_type  = {
        "fgsm":        "White-box",
        "hopskipjump": "Black-box",
        "zoo":         "Black-box",
        "cw":          "White-box",
        "deepfool":    "White-box",
    }
    _attack_blurb = {
        "fgsm":        "Requires full model internals. Single-step, fast. Represents a worst-case insider threat.",
        "hopskipjump": "Needs only predicted labels. Walks toward the decision boundary — realistic API attacker.",
        "zoo":         "Needs only probabilities. Patient gradient-estimation. Represents a persistent external attacker.",
        "cw":          "Finds the minimum-norm perturbation via Adam optimisation. Stealthier than FGSM — harder to detect statistically.",
        "deepfool":    "Iteratively crosses the nearest decision boundary with the tightest possible perturbation. The gold standard for measuring minimum-distortion robustness.",
    }
    for a in _ATTACK_KEYS:
        ast = attack_stats.get(a)
        if not ast:
            continue
        er = ast["avg_er"]
        risk = "CRITICAL" if er > 0.5 else ("HIGH" if er > 0.2 else "MODERATE")
        attack_cards.append({
            "key":        a,
            "label":      _ATTACK_LABELS.get(a, a),
            "atype":      _attack_type.get(a, ""),
            "blurb":      _attack_blurb.get(a, ""),
            "avg_er_pct": f"{er*100:.1f}%",
            "max_er_pct": f"{ast['max_er']*100:.1f}%",
            "risk":       risk,
            "risk_class": risk.lower(),
            "risk_emoji": "🔴" if er > 0.5 else ("🟡" if er > 0.2 else "🟢"),
        })

    worst_label = (
        f"{_MODEL_LABELS.get(worst_pair[0], worst_pair[0])} + "
        f"{_ATTACK_LABELS.get(worst_pair[1], worst_pair[1])}"
    ) if worst_pair else "—"

    # ── Build per-attack PoC entries ──────────────────────────────────────
    _loader_map = {
        "malware":  ("loaders.ember_loader",    "load_ember_data"),
        "ids":      ("loaders.nslkdd_loader",   "load_nslkdd_data"),
        "phishing": ("loaders.phishing_loader", "load_phishing_data"),
    }
    poc_attacks = []
    for a in _ATTACK_KEYS:
        if a not in attack_stats:
            continue
        # Pick a representative run (first model that has clean results for this attack)
        rep_model, rep_eps, rep_n = "malware", 0.05, 500
        for m in _MODEL_KEYS:
            entry = (results or {}).get(m, {}).get(a)
            if isinstance(entry, dict) and "evasion_rate" in entry and "error" not in entry:
                rep_model = m
                rep_eps   = float(entry.get("epsilon") or 0.05)
                rep_n     = int(entry.get("n_samples") or 500)
                break
        loader_mod, loader_fn_name = _loader_map.get(rep_model, ("loaders.ember_loader", "load_ember_data"))
        model_file = f"models/{rep_model}_classifier.pkl"
        template   = _POC_TEMPLATES.get(a, "")
        try:
            code = template.format(
                loader_mod=loader_mod,
                loader_fn=loader_fn_name,
                model_file=model_file,
                n_samples=rep_n,
                eps=rep_eps,
            )
        except KeyError:
            code = template
        atype = _attack_type.get(a, "")
        poc_attacks.append({
            "key":              a,
            "label":            _ATTACK_LABELS.get(a, a),
            "attack_type":      atype,
            "attack_type_class": "wb" if atype == "White-box" else "bb",
            "epsilon":          rep_eps,
            "n_samples":        rep_n,
            "model":            rep_model,
            "model_label":      _MODEL_LABELS.get(rep_model, rep_model),
            "theory":           _attack_blurb.get(a, ""),
            "code_html":        _highlight_python(code),
        })

    return {
        "max_er_pct":   f"{global_max*100:.1f}%",
        "avg_er_pct":   f"{avg_er*100:.1f}%",
        "n_tested":     len(all_er),
        "n_critical":   n_crit,
        "n_high":       n_high,
        "n_moderate":   n_mod,
        "overall_risk": risk_level,
        "risk_color":   risk_color,
        "risk_emoji":   risk_emoji,
        "plain_risk":   plain_risk,
        "action":       action,
        "worst_label":  worst_label,
        "model_cards":  model_cards,
        "attack_cards": attack_cards,
        "table_rows":   table_rows,
        "poc_attacks":  poc_attacks,
    }

app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)

# Register the Malware Lab Blueprint (all routes under /malware)
from malware_lab_bp import bp as _malware_bp
app.register_blueprint(_malware_bp)


# ---------------------------------------------------------------------------
# Landing page + lab routing
# ---------------------------------------------------------------------------

@app.get("/")
def landing():
    """Mode selector — choose ART Lab or Malware Lab."""
    return render_template("landing.html")


@app.get("/art")
def dashboard():
    """ART Lab dashboard (was previously served at /)."""
    return render_template("dashboard.html")


# ---------------------------------------------------------------------------
# API – results
# ---------------------------------------------------------------------------

@app.get("/api/results")
def api_results():
    try:
        if not os.path.exists(RESULTS_PATH):
            return jsonify({"results": {}, "note": "No results yet. Run benchmarks first."})
        with open(RESULTS_PATH) as fh:
            data = json.load(fh)
        return jsonify({"results": data})
    except Exception as exc:
        log.error("api_results error: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# API – live progress (polled by frontend every 2 s during a benchmark run)
# ---------------------------------------------------------------------------

@app.get("/api/progress")
def api_progress():
    try:
        if not os.path.exists(PROGRESS_PATH):
            return jsonify({"status": "idle"})
        with open(PROGRESS_PATH) as fh:
            data = json.load(fh)
        return jsonify(data)
    except Exception as exc:
        return jsonify({"status": "idle", "error": str(exc)})


# ---------------------------------------------------------------------------
# API – run benchmark
# ---------------------------------------------------------------------------

@app.post("/api/run-benchmark")
def api_run_benchmark():
    try:
        payload         = request.get_json(silent=True) or {}
        model           = payload.get("model", "all")
        attack          = payload.get("attack", "all")
        epsilon         = float(payload.get("epsilon", 0.05))
        use_constraints = bool(payload.get("use_constraints", False))

        # Resolve a profile name to its attack + params
        profile_key = payload.get("profile")
        if profile_key and profile_key != "custom":
            from attack_runner import ATTACK_PROFILES
            prof = ATTACK_PROFILES.get(profile_key, {})
            if not payload.get("attack"):       # only override if not explicitly set
                attack  = prof.get("attack", attack)
            if not payload.get("epsilon"):
                epsilon = prof.get("params", {}).get("eps", epsilon)

        valid_models  = {"all", "malware", "ids", "phishing"}
        valid_attacks = {"all", "fgsm", "hopskipjump", "zoo", "cw", "deepfool"}

        if model not in valid_models:
            return jsonify({"error": f"Invalid model '{model}'."}), 400
        if attack not in valid_attacks:
            return jsonify({"error": f"Invalid attack '{attack}'."}), 400
        if not (0.0 < epsilon <= 1.0):
            return jsonify({"error": "epsilon must be in (0, 1]."}), 400

        from attack_runner import run_benchmark
        results = run_benchmark(
            model_name=model, attack_name=attack,
            eps=epsilon, use_constraints=use_constraints,
        )
        params  = {"model": model, "attack": attack, "epsilon": epsilon,
                   "use_constraints": use_constraints}

        # If the frontend already has an active session, update it in-place.
        # Otherwise create a brand-new session for this run.
        incoming_sid = (payload.get("session_id") or "").strip().lower()
        valid_sid    = len(incoming_sid) == 8 and all(
            c in "0123456789abcdef" for c in incoming_sid
        )
        sid = _update_session(incoming_sid, params, results) if valid_sid \
              else _update_session(_generate_session_id(), params, results)

        return jsonify({"status": "completed", "session_id": sid, "results": results})

    except FileNotFoundError as exc:
        return jsonify({"error": f"Model files not found: {exc}. Run train_models.py first."}), 404
    except Exception as exc:
        log.error("api_run_benchmark error: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# API – attack profiles catalogue
# ---------------------------------------------------------------------------

@app.get("/api/profiles")
def api_profiles():
    try:
        from attack_runner import ATTACK_PROFILES
        return jsonify({"profiles": ATTACK_PROFILES})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# API – epsilon sweep
# ---------------------------------------------------------------------------

@app.post("/api/epsilon-sweep")
def api_epsilon_sweep():
    try:
        payload     = request.get_json(silent=True) or {}
        model       = payload.get("model", "malware")
        attack      = payload.get("attack", "fgsm")
        eps_values  = payload.get("eps_values", [0.01, 0.05, 0.1, 0.2, 0.3, 0.5])

        valid_models  = {"all", "malware", "ids", "phishing"}
        valid_attacks = {"fgsm", "hopskipjump", "zoo", "cw", "deepfool"}

        if model not in valid_models:
            return jsonify({"error": f"Invalid model '{model}'."}), 400
        if attack not in valid_attacks:
            return jsonify({"error": f"Invalid attack '{attack}'."}), 400
        if not isinstance(eps_values, list) or len(eps_values) < 2:
            return jsonify({"error": "eps_values must be a list of ≥2 floats."}), 400

        eps_values = [float(e) for e in eps_values]
        from attack_runner import run_epsilon_sweep
        result = run_epsilon_sweep(model_name=model, attack_name=attack, eps_values=eps_values)
        return jsonify(result)
    except Exception as exc:
        log.error("api_epsilon_sweep error: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# API – adversarial training defense
# ---------------------------------------------------------------------------

@app.post("/api/defend")
def api_defend():
    try:
        payload       = request.get_json(silent=True) or {}
        model         = payload.get("model", "malware")
        attack        = payload.get("attack", "fgsm")
        eps           = float(payload.get("eps", 0.05))
        augment_ratio = float(payload.get("augment_ratio", 0.3))

        valid_models  = {"malware", "ids", "phishing"}
        valid_attacks = {"fgsm", "hopskipjump", "zoo", "cw", "deepfool"}

        if model not in valid_models:
            return jsonify({"error": f"Invalid model '{model}'."}), 400
        if attack not in valid_attacks:
            return jsonify({"error": f"Invalid attack '{attack}'."}), 400
        if not (0.0 < augment_ratio <= 1.0):
            return jsonify({"error": "augment_ratio must be in (0, 1]."}), 400

        from attack_runner import apply_defense
        result = apply_defense(
            model_name=model, attack_name=attack,
            eps=eps, augment_ratio=augment_ratio,
        )
        if "error" in result:
            return jsonify(result), 500
        return jsonify(result)
    except Exception as exc:
        log.error("api_defend error: %s", exc)
        return jsonify({"error": str(exc)}), 500


@app.get("/api/defense-results")
def api_defense_results():
    try:
        if not os.path.exists(DEFENSE_PATH):
            return jsonify({"results": {}})
        with open(DEFENSE_PATH) as fh:
            return jsonify({"results": json.load(fh)})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# API – run history
# ---------------------------------------------------------------------------

@app.get("/api/history")
def api_history():
    try:
        if not os.path.exists(HISTORY_PATH):
            return jsonify({"history": []})
        with open(HISTORY_PATH) as fh:
            return jsonify({"history": json.load(fh)})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# API – constraint info
# ---------------------------------------------------------------------------

@app.get("/api/constraints")
def api_constraints():
    try:
        from loaders.feature_constraints import get_constraint_info, CONSTRAINT_DESCRIPTIONS
        info = {}
        feature_counts = {"malware": 2381, "ids": 41, "phishing": 30}
        for m, n in feature_counts.items():
            info[m] = get_constraint_info(m, n)
        return jsonify({"constraints": info, "descriptions": CONSTRAINT_DESCRIPTIONS})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# API – AI report
# ---------------------------------------------------------------------------

@app.get("/api/generate-report")
def api_generate_report():
    try:
        from report_generator import generate_report
        result = generate_report()
        if "error" in result:
            return jsonify(result), 500
        result["timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        os.makedirs("results", exist_ok=True)
        with open(REPORT_PATH, "w") as fh:
            json.dump(result, fh)
        return jsonify({**result, "redirect": "/report"})
    except Exception as exc:
        log.error("api_generate_report error: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# Report page
# ---------------------------------------------------------------------------

@app.get("/report")
def report_page():
    if not os.path.exists(REPORT_PATH):
        return redirect("/")
    try:
        with open(REPORT_PATH) as fh:
            report_data = json.load(fh)
        results = {}
        if os.path.exists(RESULTS_PATH):
            with open(RESULTS_PATH) as fh:
                results = json.load(fh)
        return render_template(
            "report.html",
            report      = report_data.get("report", ""),
            sections    = _parse_report_sections(report_data.get("report", "")),
            stats       = _compute_report_stats(results),
            source      = report_data.get("source", "unknown"),
            model_id    = report_data.get("model", "unknown"),
            timestamp   = report_data.get("timestamp", ""),
        )
    except Exception as exc:
        log.error("report_page error: %s", exc)
        return redirect("/")


# ---------------------------------------------------------------------------
# API – Session management
# ---------------------------------------------------------------------------

@app.post("/api/sessions/new")
def api_session_new():
    """
    Create a brand-new empty session immediately (no results yet).
    Returns {session_id} so the frontend can show and share the code
    before any benchmark has been run.
    """
    sid = _create_empty_session()
    return jsonify({"session_id": sid})


@app.get("/api/sessions")
def api_sessions():
    """Return lightweight metadata for all saved sessions (newest first)."""
    return jsonify({"sessions": _list_sessions()})


@app.get("/api/sessions/<sid>")
def api_session_load(sid: str):
    """Load the full results for a specific session by ID."""
    # Basic validation — session IDs are 8 lowercase hex chars
    if not sid or not all(c in "0123456789abcdef" for c in sid.lower()) or len(sid) != 8:
        return jsonify({"error": "Invalid session ID format (expected 8 hex chars)"}), 400
    path = os.path.join(SESSIONS_DIR, f"{sid}.json")
    if not os.path.exists(path):
        return jsonify({"error": f"Session '{sid}' not found"}), 404
    with open(path) as fh:
        data = json.load(fh)
    return jsonify(data)


# ---------------------------------------------------------------------------
# API – VirusTotal real-world scanning
# ---------------------------------------------------------------------------

@app.post("/api/virustotal-scan")
def api_virustotal_scan():
    """Scan a URL or look up a file SHA-256 hash on VirusTotal.
    body: {url?: str} | {hash?: str}
    Returns detection stats from 70+ real AV/security engines.
    """
    from loaders.virustotal_checker import scan_url, lookup_hash
    body = request.get_json(force=True, silent=True) or {}
    url  = (body.get("url")  or "").strip()
    sha  = (body.get("hash") or "").strip()
    if url:
        result = scan_url(url)
    elif sha:
        result = lookup_hash(sha)
    else:
        return jsonify({"error": "Provide 'url' or 'hash' in request body"}), 400
    return jsonify(result), (200 if "error" not in result else 400)


# ---------------------------------------------------------------------------
# API – HuggingFace security model targets
# ---------------------------------------------------------------------------

@app.get("/api/hf-models")
def api_hf_models():
    """Return list of available HuggingFace security model targets."""
    from loaders.hf_targets import get_model_list, SAMPLE_URLS
    return jsonify({"models": get_model_list(), "sample_urls": SAMPLE_URLS})


@app.post("/api/hf-classify")
def api_hf_classify():
    """Classify a URL with a HuggingFace security model.
    body: {model_key: str, url: str}
    """
    from loaders.hf_targets import classify_url
    body      = request.get_json(force=True, silent=True) or {}
    model_key = (body.get("model_key") or "").strip()
    url       = (body.get("url")       or "").strip()
    if not model_key or not url:
        return jsonify({"error": "Provide 'model_key' and 'url'"}), 400
    result = classify_url(model_key, url)
    return jsonify(result), (200 if "error" not in result else 400)


@app.post("/api/hf-evasion")
def api_hf_evasion():
    """Run URL mutation evasion demo against a HuggingFace security model.
    body: {model_key: str, url: str}
    Applies 6 documented URL obfuscation techniques and tests each.
    """
    from loaders.hf_targets import run_evasion_demo
    body      = request.get_json(force=True, silent=True) or {}
    model_key = (body.get("model_key") or "").strip()
    url       = (body.get("url")       or "").strip()
    if not model_key or not url:
        return jsonify({"error": "Provide 'model_key' and 'url'"}), 400
    result = run_evasion_demo(model_key, url)
    return jsonify(result), (200 if "error" not in result else 400)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    os.makedirs("results", exist_ok=True)
    os.makedirs("models", exist_ok=True)
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
