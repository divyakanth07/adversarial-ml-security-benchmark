"""
hf_targets.py — HuggingFace Inference API security model targets.

Wraps production HuggingFace text-classification models as black-box
classifiers and implements documented URL obfuscation techniques to
demonstrate real-world evasion against deployed security AI.

No local model weights needed — all inference runs via HF Inference API.
Optional: HF_TOKEN env var (increases free-tier rate limits).

URL mutation techniques implemented are all publicly documented phishing
evasion methods in academic literature (USENIX Security, IEEE S&P, etc.).
"""

import os
import re
import time
import logging
from urllib.parse import urlparse, urlunparse, quote

import httpx

log = logging.getLogger(__name__)

HF_BASE      = "https://router.huggingface.co/hf-inference/models"
_RETRY_WAIT  = 20   # seconds to wait when model is loading (cold start)
_MAX_RETRIES = 3


# ---------------------------------------------------------------------------
# Available HuggingFace security models
# ---------------------------------------------------------------------------

HF_MODELS = {
    "hf_phishing": {
        "label":              "HF Phishing Detector (BERT)",
        "model_id":           "ealvaradob/bert-finetuned-phishing",
        "task":               "phishing",
        "input_type":         "url",
        "description":        "BERT fine-tuned on phishing URL dataset. Labels: benign / phishing.",
        "positive_label_hint": "phishing",   # which label = malicious
    },
    "hf_malware_url": {
        "label":              "HF Malware URL Detector",
        "model_id":           "elftsdmr/malware-url-detect",
        "task":               "malware_url",
        "input_type":         "url",
        "description":        "Binary URL classifier trained on malicious/benign URL dataset.",
        "positive_label_hint": "malware",
    },
}

# ---------------------------------------------------------------------------
# Sample URLs for the evasion demo
# These are EXAMPLE patterns used in academic phishing research.
# Benign URLs are real public sites; phishing patterns are synthetic demos.
# ---------------------------------------------------------------------------

SAMPLE_URLS = {
    "benign": [
        "https://www.google.com/search?q=security",
        "https://github.com/login",
        "https://docs.python.org/3/",
        "https://stackoverflow.com/questions/tagged/python",
        "https://www.microsoft.com/en-us/security",
    ],
    "phishing": [
        "http://paypal-secure-verify.suspicious-login.com/account/confirm",
        "http://192.168.0.1/bank-login/verify-identity.html",
        "http://secure-update.account-microsoft.fake-demo.xyz/login",
        "http://apple-id-verify.password-reset.demo-phish.com/signin",
        "http://amazon.com.checkout-verify.phishing-example.net/cart",
    ],
}


# ---------------------------------------------------------------------------
# URL mutation / obfuscation techniques
# (all are documented in phishing literature — no real harm, demo only)
# ---------------------------------------------------------------------------

def _mutate_at_sign(url: str) -> str:
    """
    At-sign trick: browsers interpret 'google.com@evil.com' as a request
    to evil.com with 'google.com' as the username — looks legitimate at a glance.
    (CVE-style browser confusion, documented in USENIX Security research.)
    """
    p = urlparse(url)
    new_netloc = f"paypal.com@{p.netloc}"
    return urlunparse(p._replace(netloc=new_netloc))


def _mutate_subdomain_inject(url: str) -> str:
    """
    Add a trusted brand name as a subdomain to make the URL look official.
    e.g., evil.com → secure.paypal.evil.com
    """
    p = urlparse(url)
    new_netloc = f"secure.paypal.{p.netloc.lstrip('www.')}"
    return urlunparse(p._replace(netloc=new_netloc))


def _mutate_path_inject(url: str) -> str:
    """
    Inject a legitimate-looking brand domain into the URL path.
    e.g., http://evil.com/login → http://evil.com/google.com/login
    """
    p = urlparse(url)
    new_path = "/google.com" + (p.path if p.path.startswith("/") else "/" + p.path)
    return urlunparse(p._replace(path=new_path))


def _mutate_url_encode(url: str) -> str:
    """
    Partially URL-encode the domain to confuse pattern-matching detectors.
    e.g., paypal → p%61yp%61l  (replaces some 'a' chars with %61)
    """
    p = urlparse(url)
    # Encode every other vowel in the netloc
    vowels = list(re.finditer(r'[aeiou]', p.netloc, re.IGNORECASE))
    encoded_netloc = p.netloc
    for i, m in enumerate(vowels):
        if i % 2 == 0:
            c = m.group()
            encoded_netloc = encoded_netloc.replace(c, f'%{ord(c):02X}', 1)
    return urlunparse(p._replace(netloc=encoded_netloc))


def _mutate_hyphen_split(url: str) -> str:
    """
    Insert a hyphen in the middle of the domain name.
    e.g., paypal.com → pay-pal.com  — changes the lexical profile.
    """
    p = urlparse(url)
    parts = p.netloc.split('.')
    if parts:
        word = parts[0].lstrip('www')
        mid  = max(1, len(word) // 2)
        parts[0] = word[:mid] + '-' + word[mid:]
    return urlunparse(p._replace(netloc='.'.join(parts)))


def _mutate_tld_swap(url: str) -> str:
    """
    Swap the TLD to .org or .net to change the statistical signature.
    e.g., evil.com → evil.net
    """
    p = urlparse(url)
    parts = p.netloc.rsplit('.', 1)
    new_netloc = parts[0] + '.net' if len(parts) == 2 else p.netloc
    return urlunparse(p._replace(netloc=new_netloc))


# Ordered list of mutations shown in the evasion demo
MUTATIONS = [
    ("original",         "Original (no mutation)",              lambda u: u),
    ("at_sign",          "@ trick (brand as username)",         _mutate_at_sign),
    ("subdomain_inject", "Subdomain injection (brand prefix)",  _mutate_subdomain_inject),
    ("path_inject",      "Path injection (brand in path)",      _mutate_path_inject),
    ("url_encode",       "Partial URL encoding (vowels)",       _mutate_url_encode),
    ("hyphen_split",     "Hyphen split (lexical confusion)",    _mutate_hyphen_split),
    ("tld_swap",         "TLD swap (.com → .net)",              _mutate_tld_swap),
]


# ---------------------------------------------------------------------------
# HuggingFace Inference API client
# ---------------------------------------------------------------------------

def _hf_headers() -> dict:
    token = os.environ.get("HF_TOKEN", "").strip()
    h = {"Content-Type": "application/json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _hf_post(model_id: str, text: str) -> dict:
    """
    Call the HuggingFace Inference Router for text-classification.
    Handles cold-start 503 retries and multiple response envelope formats.
    Returns {"label": str, "score": float, "raw": list}
    """
    url = f"{HF_BASE}/{model_id}"
    payload = {"inputs": text}

    for attempt in range(_MAX_RETRIES):
        try:
            r = httpx.post(url, headers=_hf_headers(), json=payload, timeout=60)

            if r.status_code == 503:
                # Model is loading (cold start) — wait and retry
                try:
                    est = r.json().get("estimated_time", _RETRY_WAIT)
                except Exception:
                    est = _RETRY_WAIT
                wait = min(float(est), 30)
                log.info("HF model loading, waiting %.0fs (attempt %d/%d)",
                         wait, attempt + 1, _MAX_RETRIES)
                time.sleep(wait)
                continue

            if r.status_code == 401:
                return {"error": "Invalid or missing HF_TOKEN — set it in your .env file"}
            if r.status_code == 404:
                return {"error": f"Model '{model_id}' not found on HuggingFace Router"}
            if r.status_code != 200:
                log.warning("HF Router %s → HTTP %d: %s", model_id, r.status_code, r.text[:300])
                return {"error": f"HF API error {r.status_code}: {r.text[:200]}"}

            data = r.json()
            log.debug("HF raw response: %s", str(data)[:200])

            # ── Normalise the many possible response envelopes ────────────
            # New router: {"outputs": [[{label, score}]]} or {"outputs": [{label, score}]}
            if isinstance(data, dict):
                data = data.get("outputs", data.get("predictions", []))

            # Classic API: [[{label, score}]] → unwrap outer list
            if isinstance(data, list) and data and isinstance(data[0], list):
                data = data[0]

            # Ensure we now have [{label, score}, ...]
            if not isinstance(data, list) or not data:
                return {"error": f"Unexpected HF response format: {str(r.text)[:150]}"}

            if not isinstance(data[0], dict):
                return {"error": f"Unexpected HF item format: {str(data[0])[:100]}"}

            # Sort by score descending and return top prediction
            data.sort(key=lambda x: x.get("score", 0), reverse=True)
            top = data[0]
            return {
                "label": top.get("label", "unknown").lower(),
                "score": round(top.get("score", 0.0), 4),
                "raw":   data,
            }

        except httpx.TimeoutException:
            return {"error": "HuggingFace API request timed out (60s) — model may be cold-starting"}
        except Exception as exc:
            log.exception("HF API call error")
            return {"error": str(exc)}

    return {"error": f"HF model still loading after {_MAX_RETRIES} retries — try again in a minute"}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def classify_url(model_key: str, url: str) -> dict:
    """
    Classify a single URL using a HuggingFace security model.

    Returns:
        {label, score, is_malicious, model_key, url}
    Or  {error, model_key, url}
    """
    model_info = HF_MODELS.get(model_key)
    if not model_info:
        return {"error": f"Unknown model key '{model_key}'", "model_key": model_key, "url": url}

    result = _hf_post(model_info["model_id"], url)
    if "error" in result:
        result["model_key"] = model_key
        result["url"]       = url
        return result

    hint = model_info.get("positive_label_hint", "malicious").lower()
    is_malicious = (hint in result["label"]) or result["label"] in ("1", "malicious", "phishing", "spam")

    return {
        "model_key":    model_key,
        "model_label":  model_info["label"],
        "url":          url,
        "label":        result["label"],
        "score":        result["score"],
        "is_malicious": is_malicious,
        "raw":          result.get("raw", []),
    }


def run_evasion_demo(model_key: str, url: str) -> dict:
    """
    Apply all URL mutation techniques to a given URL and test each variant
    against the selected HuggingFace security model.

    Returns:
        {
          "model_key": ...,
          "original_url": ...,
          "results": [
            {"mutation_key", "mutation_label", "mutated_url",
             "label", "score", "is_malicious", "evaded"},
            ...
          ],
          "n_evaded": int,
          "n_total":  int,
          "evasion_rate": float,
        }
    """
    model_info = HF_MODELS.get(model_key)
    if not model_info:
        return {"error": f"Unknown model key '{model_key}'"}

    results = []
    for mut_key, mut_label, mut_fn in MUTATIONS:
        mutated_url = mut_fn(url)
        classification = _hf_post(model_info["model_id"], mutated_url)

        if "error" in classification:
            results.append({
                "mutation_key":   mut_key,
                "mutation_label": mut_label,
                "mutated_url":    mutated_url,
                "error":          classification["error"],
            })
            continue

        hint         = model_info.get("positive_label_hint", "malicious").lower()
        is_malicious = (hint in classification["label"]) or classification["label"] in ("1", "malicious", "phishing")
        results.append({
            "mutation_key":   mut_key,
            "mutation_label": mut_label,
            "mutated_url":    mutated_url,
            "label":          classification["label"],
            "score":          classification["score"],
            "is_malicious":   is_malicious,
            "evaded":         not is_malicious,    # evaded = classified as benign
        })

    valid   = [r for r in results if "error" not in r]
    n_evaded = sum(1 for r in valid if r.get("evaded"))
    n_total  = len(valid)

    return {
        "model_key":    model_key,
        "model_label":  model_info["label"],
        "original_url": url,
        "results":      results,
        "n_evaded":     n_evaded,
        "n_total":      n_total,
        "evasion_rate": round(n_evaded / n_total, 3) if n_total else 0.0,
    }


def get_model_list() -> list:
    """Return serialisable list of available HF model descriptions."""
    return [
        {
            "key":         k,
            "label":       v["label"],
            "description": v["description"],
            "task":        v["task"],
        }
        for k, v in HF_MODELS.items()
    ]
