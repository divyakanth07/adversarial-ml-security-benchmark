"""
feature_constraints.py — Domain-realistic feature mutability masks.

Each mask is a numpy array of shape (n_features,):
  1.0 = MUTABLE   — attacker can perturb this feature without breaking validity
  0.0 = IMMUTABLE — perturbing would break file/protocol validity or is unrealistic

Applied post-generation to make adversarial examples domain-realistic:
  X_realistic = X_clean + mask * (X_adv - X_clean)

Usage:
  from loaders.feature_constraints import apply_constraints
  X_adv_constrained = apply_constraints("malware", X_clean, X_adv)
"""

import numpy as np


def get_malware_mask(n_features: int = 2381) -> np.ndarray:
    """
    EMBER-style PE feature space (approximate layout):
      [0:256]    Byte histogram          — MUTABLE   (add padding/junk bytes freely)
      [256:512]  Byte-entropy histogram  — MUTABLE   (follows from byte content changes)
      [512:531]  PE general info         — IMMUTABLE (altering PE header breaks executability)
      [531:555]  Section info            — MUTABLE   (add overlay sections, not critical ones)
      [555:575]  Import table info       — IMMUTABLE (removing imports breaks execution)
      [575:623]  Export table info       — MUTABLE   (extra exports are valid)
      [623:2381] String/printable feats  — MUTABLE   (inject benign-looking strings freely)

    Realistic attack: append benign byte sequences, inject junk strings,
    add overlay sections. Cannot touch PE header or import table.
    """
    mask = np.ones(n_features, dtype=np.float32)
    # PE header fields — altering breaks the executable format
    if n_features > 531:
        mask[512:min(531, n_features)] = 0.0
    # Import table — altering breaks runtime linking
    if n_features > 575:
        mask[555:min(575, n_features)] = 0.0
    return mask


def get_nslkdd_mask(n_features: int = 41) -> np.ndarray:
    """
    NSL-KDD network flow feature layout (standard 41-feature ordering):
      0   duration              — MUTABLE  (attacker can control connection length)
      1   protocol_type         — IMMUTABLE (TCP/UDP/ICMP determined by socket; can't lie)
      2   service               — IMMUTABLE (determined by destination port; cannot fake)
      3   flag                  — IMMUTABLE (TCP state machine enforces this)
      4   src_bytes             — MUTABLE  (attacker controls data volume)
      5   dst_bytes             — MUTABLE
      6   land                  — IMMUTABLE (src/dst IP equality; network enforces this)
      7   wrong_fragment        — MUTABLE  (can craft abnormal fragments)
      8   urgent                — MUTABLE  (can set URG flag)
      9-40 statistical/content  — MUTABLE  (attacker controls payload content and timing)

    Realistic attack: vary payload size, connection duration, fragment behavior.
    Cannot fake TCP state flags, protocol type, or service mapping.
    """
    mask = np.ones(n_features, dtype=np.float32)
    if n_features > 1:
        mask[1] = 0.0   # protocol_type
    if n_features > 2:
        mask[2] = 0.0   # service
    if n_features > 3:
        mask[3] = 0.0   # flag
    if n_features > 6:
        mask[6] = 0.0   # land
    return mask


def get_phishing_mask(n_features: int = 30) -> np.ndarray:
    """
    UCI Phishing Websites feature layout (30-feature standard set):
      0-9   URL-structure features    — MUTABLE   (attacker owns the URL)
      10-13 Domain registration info  — MUTABLE   (register new look-alike domains)
      14    domain_age_of_domain      — IMMUTABLE (domain age is fixed; can't fake old age)
      15    dns_record                — IMMUTABLE (authoritative DNS cannot be easily forged)
      16-19 Web traffic / reputation  — MUTABLE   (can buy traffic, create backlinks)
      20-29 HTML page-content feats   — MUTABLE   (attacker controls all page content)

    Realistic attack: craft convincing URL structure, clone legitimate page content,
    drive traffic. Cannot make a newly registered domain appear old in WHOIS.
    """
    mask = np.ones(n_features, dtype=np.float32)
    if n_features > 14:
        mask[14] = 0.0  # domain_age_of_domain
    if n_features > 15:
        mask[15] = 0.0  # dns_record
    return mask


# Registry: model_name → mask factory function
CONSTRAINT_MASKS = {
    "malware":  get_malware_mask,
    "ids":      get_nslkdd_mask,
    "phishing": get_phishing_mask,
}

# Human-readable descriptions (for UI display)
CONSTRAINT_DESCRIPTIONS = {
    "malware": {
        "mutable":   "Byte content, string sections, overlay data",
        "immutable": "PE header fields, import table",
        "rationale": "Perturbing PE structure or imports would break the binary's executability.",
    },
    "ids": {
        "mutable":   "Payload size, connection duration, fragment flags",
        "immutable": "Protocol type, service port mapping, TCP state flags",
        "rationale": "Network stack enforces protocol type and TCP state; these cannot be spoofed.",
    },
    "phishing": {
        "mutable":   "URL structure, page content, traffic patterns",
        "immutable": "Domain age (WHOIS), authoritative DNS records",
        "rationale": "A freshly registered phishing domain cannot appear years old in WHOIS records.",
    },
}


def apply_constraints(
    model_name: str,
    X_clean: np.ndarray,
    X_adv: np.ndarray,
) -> np.ndarray:
    """
    Apply domain-specific feature constraints to adversarial examples.
    Immutable features are reset to their original clean values.

    Returns a new array with the same shape as X_adv.
    """
    mask_fn = CONSTRAINT_MASKS.get(model_name)
    if mask_fn is None:
        return X_adv
    n_features = X_clean.shape[1]
    mask = mask_fn(n_features).reshape(1, -1)   # broadcast over batch
    return (X_clean + mask * (X_adv - X_clean)).astype(X_adv.dtype)


def get_constraint_info(model_name: str, n_features: int) -> dict:
    """Return constraint statistics for a given model/feature count."""
    mask_fn = CONSTRAINT_MASKS.get(model_name)
    if mask_fn is None:
        return {"n_mutable": n_features, "n_immutable": 0, "pct_mutable": 100.0}
    mask = mask_fn(n_features)
    n_mut = int(mask.sum())
    n_imm = n_features - n_mut
    desc  = CONSTRAINT_DESCRIPTIONS.get(model_name, {})
    return {
        "n_mutable":   n_mut,
        "n_immutable": n_imm,
        "pct_mutable": round(100.0 * n_mut / n_features, 1),
        "mutable_desc":   desc.get("mutable", ""),
        "immutable_desc": desc.get("immutable", ""),
        "rationale":      desc.get("rationale", ""),
    }
