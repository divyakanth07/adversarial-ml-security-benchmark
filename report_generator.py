"""
report_generator.py — Security report generator with Claude Haiku + rule-based fallback.

Strategy:
  1. Attempt to call Claude Haiku via the Anthropic API.
  2. If the API is unavailable (billing error, missing key, network issue),
     automatically fall back to a deterministic rule-based report that derives
     all findings directly from benchmark_results.json.

Both paths produce the same four-section structure:
  1. Executive Summary
  2. Per-Model Vulnerability Analysis
  3. Attack Effectiveness Comparison
  4. Defensive Recommendations

Usage:
    python report_generator.py          # prints report to stdout
    Imported by app.py for /api/generate-report
"""

import os
import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from dotenv import load_dotenv

load_dotenv()
log = logging.getLogger(__name__)

RESULTS_PATH = os.path.join("results", "benchmark_results.json")
MODEL_ID     = "claude-haiku-4-5"

SYSTEM_PROMPT = (
    "You are a senior cybersecurity analyst specialising in adversarial machine learning. "
    "You have been given benchmark results from an adversarial ML toolkit that tested three "
    "security classifiers (malware detection, network intrusion detection, phishing detection) "
    "against three attack methods (FGSM, HopSkipJump, ZooAttack).\n\n"
    "Produce a structured threat analysis report with exactly these four sections:\n"
    "1. Executive Summary — a concise 3–5 sentence overview of overall risk posture.\n"
    "2. Per-Model Vulnerability Analysis — discuss each classifier's weaknesses.\n"
    "3. Attack Effectiveness Comparison — compare the three attack methods.\n"
    "4. Defensive Recommendations — a numbered list of concrete mitigations.\n\n"
    "Classification rules for evasion rates:\n"
    "  - evasion_rate > 0.50  → label as CRITICAL\n"
    "  - 0.20 < evasion_rate ≤ 0.50 → label as HIGH\n"
    "  - evasion_rate ≤ 0.20  → label as MODERATE\n\n"
    "Be precise and technical. Do not include any preamble or sign-off."
)

_MODEL_NAMES  = {"malware": "Malware Classifier (RandomForest)",
                 "ids":     "IDS Classifier (GradientBoosting)",
                 "phishing":"Phishing Classifier (LogisticRegression)"}
_ATTACK_NAMES = {"fgsm": "FGSM", "hopskipjump": "HopSkipJump", "zoo": "ZooAttack"}
_ATTACK_ORDER = ["fgsm", "hopskipjump", "zoo"]
_MODEL_ORDER  = ["malware", "ids", "phishing"]


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _risk_label(er: float) -> str:
    if er > 0.50: return "CRITICAL"
    if er > 0.20: return "HIGH"
    return "MODERATE"


def _risk_emoji(er: float) -> str:
    if er > 0.50: return "🔴 CRITICAL"
    if er > 0.20: return "🟡 HIGH"
    return "🟢 MODERATE"


def _collect_metrics(results: Dict) -> Tuple[Dict, List[float]]:
    """
    Returns (model_data, all_evasion_rates) where model_data is:
      { model: { attack: metrics_dict } }
    Only entries with a valid evasion_rate are included.
    """
    model_data: Dict[str, Dict] = {}
    all_er: List[float] = []
    for model in _MODEL_ORDER:
        attacks = results.get(model, {})
        if not isinstance(attacks, dict):
            continue
        model_data[model] = {}
        for attack in _ATTACK_ORDER:
            m = attacks.get(attack)
            if not isinstance(m, dict) or "error" in m or "evasion_rate" not in m:
                continue
            model_data[model][attack] = m
            all_er.append(float(m["evasion_rate"]))
    return model_data, all_er


def _format_markdown_table(results: Dict) -> str:
    header = (
        "| Model | Attack | Original Acc | Post-Attack Acc | "
        "Evasion Rate | Confidence Delta | Risk Level |\n"
        "|-------|--------|:------------:|:---------------:|"
        ":------------:|:----------------:|:----------:|"
    )
    rows = []
    model_data, _ = _collect_metrics(results)
    for model, attacks in model_data.items():
        for attack, m in attacks.items():
            er = m["evasion_rate"]
            rows.append(
                f"| {_MODEL_NAMES.get(model, model)} | {_ATTACK_NAMES.get(attack, attack)} "
                f"| {m.get('original_accuracy','N/A')} "
                f"| {m.get('post_attack_accuracy','N/A')} "
                f"| {er:.1%} "
                f"| {m.get('confidence_delta','N/A')} "
                f"| {_risk_emoji(er)} |"
            )
    return (header + "\n" + "\n".join(rows)) if rows else "No valid benchmark data."


# ---------------------------------------------------------------------------
# Rule-based fallback report
# ---------------------------------------------------------------------------

def _generate_fallback_report(results: Dict) -> str:
    model_data, all_er = _collect_metrics(results)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    max_er  = max(all_er) if all_er else 0.0
    avg_er  = (sum(all_er) / len(all_er)) if all_er else 0.0
    overall = _risk_label(max_er)

    L: List[str] = []
    sep = "─" * 62

    L += [sep,
          "  ADVERSARIAL ML SECURITY BENCHMARK REPORT",
          f"  Generated : {now}",
          f"  Source    : Rule-based analysis  (Claude API unavailable)",
          sep, ""]

    # ── 1. Executive Summary ──────────────────────────────────────────────
    n_models  = sum(1 for d in model_data.values() if d)
    n_attacks = len({a for d in model_data.values() for a in d})

    L.append("1. EXECUTIVE SUMMARY")
    L.append("─" * 40)
    L.append(
        f"Benchmarks were run across {n_models} security classifier(s) and "
        f"{n_attacks} adversarial attack method(s), producing {len(all_er)} "
        f"attack–model result(s). The overall risk posture is {overall} "
        f"(max evasion {max_er:.1%}, avg {avg_er:.1%})."
    )
    if max_er > 0.50:
        L.append(
            "At least one combination reached a CRITICAL evasion rate — adversarial "
            "examples can reliably bypass detection. Immediate adversarial hardening "
            "is required before production deployment."
        )
    elif max_er > 0.20:
        L.append(
            "Several combinations show HIGH evasion rates, indicating meaningful "
            "adversarial vulnerability. Targeted defences (adversarial training, "
            "input validation) should be applied before production deployment."
        )
    else:
        L.append(
            "All combinations show MODERATE evasion rates, suggesting reasonable "
            "baseline robustness. Continued monitoring and periodic re-benchmarking "
            "are still recommended as the threat landscape evolves."
        )
    L.append("")

    # ── 2. Per-Model Vulnerability Analysis ──────────────────────────────
    L.append("2. PER-MODEL VULNERABILITY ANALYSIS")
    L.append("─" * 40)

    _model_commentary = {
        "malware": (
            "The malware classifier operates on a 2381-feature PE representation. "
            "Its high dimensionality makes gradient-based white-box attacks (FGSM) less "
            "efficient per feature, but black-box boundary attacks can still find adversarial "
            "regions by exploiting the classifier's decision surface."
        ),
        "ids": (
            "The IDS classifier uses 41 network flow features. Its compact feature space "
            "makes it particularly susceptible to black-box attacks; small perturbations to "
            "packet timing or byte-count features can shift predictions from 'attack' to 'normal'."
        ),
        "phishing": (
            "The phishing classifier uses 30 URL/page features with a linear decision boundary "
            "(LogisticRegression). Linear models expose their gradient analytically, making "
            "them highly susceptible to FGSM, while the simple boundary also aids black-box methods."
        ),
    }

    for model in _MODEL_ORDER:
        attacks = model_data.get(model, {})
        name = _MODEL_NAMES.get(model, model)
        if not attacks:
            L.append(f"▸ {name}")
            L.append("  No benchmark data available for this model.")
            L.append("")
            continue

        er_vals   = [m["evasion_rate"] for m in attacks.values()]
        max_m_er  = max(er_vals)
        avg_m_er  = sum(er_vals) / len(er_vals)
        worst_atk = max(attacks.items(), key=lambda x: x[1]["evasion_rate"])[0]
        orig_acc  = next(iter(attacks.values())).get("original_accuracy", "N/A")

        L.append(f"▸ {name}  [{_risk_emoji(max_m_er)}]")
        if isinstance(orig_acc, float):
            L.append(f"  Baseline accuracy : {orig_acc:.4f}")
        L.append(f"  Max evasion rate  : {max_m_er:.1%}  (worst attack: {_ATTACK_NAMES.get(worst_atk, worst_atk)})")
        L.append(f"  Avg evasion rate  : {avg_m_er:.1%}")
        L.append("")
        # Wrap commentary at 70 chars
        commentary = _model_commentary.get(model, "")
        words, line = commentary.split(), ""
        for w in words:
            if len(line) + len(w) + 1 > 68:
                L.append("  " + line)
                line = w
            else:
                line = (line + " " + w).strip()
        if line:
            L.append("  " + line)
        L.append("")

    # ── 3. Attack Effectiveness Comparison ───────────────────────────────
    L.append("3. ATTACK EFFECTIVENESS COMPARISON")
    L.append("─" * 40)

    _attack_desc = {
        "fgsm": (
            "FGSM (white-box) — Requires full model gradient access. "
            "Single-step method; fastest attack but limited by the requirement for "
            "internal model knowledge. Reveals the theoretical worst-case gradient exposure."
        ),
        "hopskipjump": (
            "HopSkipJump (black-box) — Requires only class-label predictions. "
            "Iteratively binary-searches toward the decision boundary. Realistic threat "
            "model for API-exposed classifiers where only the predicted label is returned."
        ),
        "zoo": (
            "ZooAttack (black-box) — Requires only prediction probabilities. "
            "Estimates gradients via finite differences and applies Adam optimisation. "
            "Slowest but most widely applicable; represents a persistent, patient attacker."
        ),
    }

    attack_summary = []
    for attack in _ATTACK_ORDER:
        rates = [model_data[m][attack]["evasion_rate"]
                 for m in _MODEL_ORDER if attack in model_data.get(m, {})]
        if rates:
            attack_summary.append((attack, sum(rates)/len(rates), max(rates)))

    attack_summary.sort(key=lambda x: x[1], reverse=True)

    for attack, avg_a_er, max_a_er in attack_summary:
        L.append(f"▸ {_ATTACK_NAMES.get(attack, attack)}  [{_risk_label(max_a_er)}]")
        L.append(f"  Avg evasion: {avg_a_er:.1%}   Max evasion: {max_a_er:.1%}")
        desc = _attack_desc.get(attack, "")
        words, line = desc.split(), ""
        for w in words:
            if len(line) + len(w) + 1 > 68:
                L.append("  " + line)
                line = w
            else:
                line = (line + " " + w).strip()
        if line:
            L.append("  " + line)
        L.append("")

    if attack_summary:
        best = attack_summary[0]
        L.append(
            f"Most effective attack: {_ATTACK_NAMES.get(best[0], best[0])} "
            f"(avg evasion {best[1]:.1%})"
        )
    L.append("")

    # ── 4. Defensive Recommendations ─────────────────────────────────────
    L.append("4. DEFENSIVE RECOMMENDATIONS")
    L.append("─" * 40)

    recs = [
        ("Adversarial Training",
         f"Augment training data with adversarial examples from FGSM (ε=0.05) and "
         f"HopSkipJump. Even a single retraining round typically reduces evasion rates by "
         f"30–60%. Priority: {'IMMEDIATE' if max_er > 0.50 else 'HIGH'}."),

        ("Feature Squeezing",
         "Apply pre-processing defences (bit-depth reduction, median filtering on continuous "
         "features) before inference. This disrupts small adversarial perturbations at minimal "
         "cost to clean accuracy."),

        ("Ensemble Diversity",
         "Deploy an ensemble of structurally diverse classifiers. Attacks optimised against "
         "one model generalise poorly to others, reducing cross-model evasion rates "
         "significantly."),

        ("Confidence Thresholding",
         f"Reject predictions with max-class probability < 0.75 and escalate to human review. "
         f"The benchmark shows an avg confidence delta of "
         f"{avg_er:.2f} across combinations — thresholding directly addresses this drop."),

        ("Input Anomaly Detection",
         "Flag inputs whose feature distributions deviate significantly (>3σ) from the training "
         "set. Adversarial examples often lie near decision boundaries and exhibit anomalous "
         "statistical properties."),

        ("Quarterly Re-Benchmarking",
         "Schedule adversarial benchmarks every quarter with updated attack parameters. "
         "Defences trained against known attacks degrade against newer methods if not retested."),

        ("API Rate-Limiting & Query Monitoring",
         "Black-box attacks (HopSkipJump, ZooAttack) require many repeated queries. "
         "Detect and throttle clients making anomalous prediction volumes to disrupt "
         "gradient-estimation campaigns."),
    ]

    for i, (title, body) in enumerate(recs, 1):
        L.append(f"{i}. {title}")
        words, line = body.split(), ""
        for w in words:
            if len(line) + len(w) + 1 > 68:
                L.append("   " + line)
                line = w
            else:
                line = (line + " " + w).strip()
        if line:
            L.append("   " + line)
        L.append("")

    L.append(sep)
    return "\n".join(L)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_report(results: Optional[Dict] = None) -> Dict:
    """
    Generate a security report.

    Tries Claude Haiku first; falls back to the rule-based generator if the
    API is unavailable (billing error, missing key, network failure, etc.).

    Returns dict with keys:
      "report"  — the report text
      "model"   — model ID used, or "rule-based"
      "source"  — "claude" | "fallback"
    Or {"error": ...} if even the fallback fails.
    """
    # ── Load results ──────────────────────────────────────────────────────
    if results is None:
        if not os.path.exists(RESULTS_PATH):
            return {
                "error": (
                    "No benchmark results found. "
                    "Run benchmarks first via the dashboard or attack_runner.py."
                )
            }
        try:
            with open(RESULTS_PATH) as fh:
                results = json.load(fh)
        except Exception as exc:
            return {"error": f"Failed to read results file: {exc}"}

    # ── Attempt Claude API ────────────────────────────────────────────────
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()

    if api_key:
        table       = _format_markdown_table(results)
        user_prompt = (
            "Please analyse the following adversarial ML benchmark results and produce "
            "the security report:\n\n" + table
        )
        try:
            import anthropic
            client  = anthropic.Anthropic(api_key=api_key)
            message = client.messages.create(
                model=MODEL_ID,
                max_tokens=2048,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_prompt}],
            )
            return {
                "report": message.content[0].text,
                "model":  MODEL_ID,
                "source": "claude",
            }
        except ImportError:
            log.warning("anthropic package not installed — using rule-based fallback.")
        except Exception as exc:
            # Log the API error and fall through to the rule-based fallback
            log.warning("Claude API unavailable (%s) — using rule-based fallback.", exc)
    else:
        log.info("ANTHROPIC_API_KEY not set — using rule-based fallback.")

    # ── Rule-based fallback ───────────────────────────────────────────────
    try:
        report_text = _generate_fallback_report(results)
        return {
            "report": report_text,
            "model":  "rule-based",
            "source": "fallback",
        }
    except Exception as exc:
        log.error("Fallback report generation failed: %s", exc)
        return {"error": f"Report generation failed: {exc}"}


if __name__ == "__main__":
    result = generate_report()
    if "error" in result:
        print(f"ERROR: {result['error']}")
    else:
        src = result.get("source", "?")
        print(f"[Source: {src}  |  Model: {result.get('model','?')}]\n")
        print(result["report"])
