"""
virustotal_checker.py — VirusTotal API v3 integration.

Submits URLs and file hashes to VirusTotal and returns detection results
from 70+ real-world AV/security engines.

Requires:  VIRUSTOTAL_API_KEY env var  (free key at virustotal.com)
Uses:      httpx (already in requirements.txt)

Free tier limits: 4 requests / minute, 500 / day.
"""

import os
import time
import base64
import logging
from urllib.parse import urlencode

import httpx

log = logging.getLogger(__name__)

VT_BASE    = "https://www.virustotal.com/api/v3"
_POLL_WAIT = 15   # seconds between polls (stays within 4 req/min free limit)
_MAX_POLLS = 4    # give up after this many polls


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_key() -> str:
    return os.environ.get("VIRUSTOTAL_API_KEY", "").strip()


def _headers() -> dict:
    return {"x-apikey": _get_key(), "accept": "application/json"}


def _parse_stats(attributes: dict) -> dict:
    """Normalise a VT attributes block into a clean summary dict."""
    # VT uses different key names for URL vs file reports
    stats = attributes.get("stats") or attributes.get("last_analysis_stats") or {}
    results_raw = (
        attributes.get("results") or
        attributes.get("last_analysis_results") or {}
    )

    malicious  = int(stats.get("malicious",  0))
    suspicious = int(stats.get("suspicious", 0))
    undetected = int(stats.get("undetected", 0))
    harmless   = int(stats.get("harmless",   0))
    total      = malicious + suspicious + undetected + harmless

    # Per-engine breakdown (only engines that flagged something)
    flagging_engines = []
    for engine_name, info in results_raw.items():
        cat = info.get("category", "")
        if cat in ("malicious", "suspicious", "phishing"):
            flagging_engines.append({
                "engine":   engine_name,
                "category": cat,
                "result":   info.get("result") or cat,
            })
    flagging_engines.sort(key=lambda x: (x["category"], x["engine"]))

    pct = round((malicious + suspicious) / total * 100, 1) if total else 0.0
    return {
        "malicious":       malicious,
        "suspicious":      suspicious,
        "undetected":      undetected,
        "harmless":        harmless,
        "total":           total,
        "detection_ratio": f"{malicious + suspicious} / {total}",
        "detection_pct":   pct,
        "risk":            ("CRITICAL" if pct > 50 else "HIGH" if pct > 20 else "LOW"),
        "flagging_engines": flagging_engines[:40],   # cap for UI
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_url(url: str) -> dict:
    """
    Submit a URL to VirusTotal for scanning and return detection results.

    Workflow:
      1. Try to fetch an existing cached report (instant, no quota cost).
      2. If none found, submit the URL for a fresh scan then poll for results.

    Returns a dict with keys:
        malicious, suspicious, undetected, harmless, total,
        detection_ratio, detection_pct, risk, flagging_engines
    Or {"error": "..."} on failure.
    """
    key = _get_key()
    if not key:
        return {"error": "VIRUSTOTAL_API_KEY is not set. Add it to your .env file."}

    try:
        with httpx.Client(timeout=30) as client:
            # ── Step 1: try existing cached report ──────────────────────────
            encoded = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
            r = client.get(f"{VT_BASE}/urls/{encoded}", headers=_headers())
            if r.status_code == 200:
                attrs = r.json().get("data", {}).get("attributes", {})
                result = _parse_stats(attrs)
                result["cached"] = True
                result["url"]    = url
                return result

            # ── Step 2: submit for fresh scan ───────────────────────────────
            r = client.post(
                f"{VT_BASE}/urls",
                headers={**_headers(), "content-type": "application/x-www-form-urlencoded"},
                content=urlencode({"url": url}),   # properly encodes ://, ?, & etc.
            )
            if r.status_code not in (200, 201):
                return {"error": f"VT submission failed (HTTP {r.status_code}): {r.text[:200]}"}

            analysis_id = r.json().get("data", {}).get("id", "")
            if not analysis_id:
                return {"error": "VT did not return an analysis ID"}

            # ── Step 3: poll for results ─────────────────────────────────────
            for attempt in range(_MAX_POLLS):
                time.sleep(_POLL_WAIT)
                r2 = client.get(f"{VT_BASE}/analyses/{analysis_id}", headers=_headers())
                if r2.status_code == 200:
                    data  = r2.json().get("data", {})
                    attrs = data.get("attributes", {})
                    if attrs.get("status") == "completed":
                        result = _parse_stats(attrs)
                        result["cached"] = False
                        result["url"]    = url
                        return result
                log.info("VT poll %d/%d: status=%s", attempt + 1, _MAX_POLLS,
                         r2.json().get("data", {}).get("attributes", {}).get("status", "?"))

            return {"error": "VT analysis timed out — try again in a moment"}

    except httpx.TimeoutException:
        return {"error": "Request to VirusTotal timed out"}
    except Exception as exc:
        log.exception("VT scan_url error")
        return {"error": str(exc)}


def lookup_hash(sha256: str) -> dict:
    """
    Look up a file by SHA-256 hash on VirusTotal.

    Returns the same stats dict as scan_url, plus:
        file_name, file_type, file_size
    """
    key = _get_key()
    if not key:
        return {"error": "VIRUSTOTAL_API_KEY is not set. Add it to your .env file."}

    sha256 = sha256.strip().lower()
    if len(sha256) != 64 or not all(c in "0123456789abcdef" for c in sha256):
        return {"error": "Invalid SHA-256 hash — must be 64 hex characters"}

    try:
        with httpx.Client(timeout=20) as client:
            r = client.get(f"{VT_BASE}/files/{sha256}", headers=_headers())
            if r.status_code == 404:
                return {"error": "Hash not found in VirusTotal database — it may not have been submitted yet"}
            if r.status_code == 401:
                return {"error": "Invalid VirusTotal API key"}
            if r.status_code != 200:
                return {"error": f"VT lookup failed (HTTP {r.status_code})"}

            attrs  = r.json().get("data", {}).get("attributes", {})
            result = _parse_stats(attrs)
            result["file_name"] = (
                attrs.get("meaningful_name") or
                (attrs.get("names") or [sha256[:16] + "…"])[0]
            )
            result["file_type"] = attrs.get("type_description", "Unknown")
            result["file_size"] = attrs.get("size", 0)
            result["sha256"]    = sha256
            return result

    except httpx.TimeoutException:
        return {"error": "Request to VirusTotal timed out"}
    except Exception as exc:
        log.exception("VT lookup_hash error")
        return {"error": str(exc)}
