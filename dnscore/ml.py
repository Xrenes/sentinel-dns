"""Heuristic domain-risk model ("heuristic-v0").

Scores a domain between 0 and 1 from lexical features that separate algorithmically
generated (DGA) and phishing-style names from normal ones. A trained model
(Random Forest / character CNN) can replace :func:`score_domain` later while keeping
the same :class:`MlResult` contract.
"""
from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field

MODEL_NAME = "heuristic-v0"
BIAS = -3.2
MALICIOUS_AT = 0.85
SUSPICIOUS_AT = 0.6
MIN_REASON_WEIGHT = 0.25

VOWELS = frozenset("aeiou")
MULTI_PART_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.in", "co.jp",
    "com.bd", "edu.bd", "ac.bd", "gov.bd", "org.bd", "net.bd", "com.br", "com.cn", "co.za",
})
SUSPICIOUS_TLDS = frozenset({
    "top", "xyz", "biz", "info", "click", "link", "work", "online", "gq", "tk", "ml",
    "cf", "ga", "zip", "mov", "rest", "kim", "loan", "win", "country",
})
KEYWORDS = (
    "login", "signin", "verify", "secure", "account", "update", "bank", "wallet", "confirm",
    "password", "billing", "paypa1", "appleid", "prize", "bonus", "claim", "unlock", "recover",
    "suspended",
)


@dataclass(frozen=True)
class MlResult:
    score: float
    label: str
    reasons: tuple[str, ...] = ()
    features: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "label": self.label,
            "reasons": list(self.reasons),
            "features": dict(self.features),
            "model": MODEL_NAME,
        }


def _registrable(labels: list[str]) -> tuple[str, list[str], str]:
    """Split labels into (second-level label, subdomain labels, public suffix)."""
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return labels[-3], labels[:-3], ".".join(labels[-2:])
    return labels[-2], labels[:-2], labels[-1]


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    total = len(text)
    return -sum(count / total * math.log2(count / total) for count in Counter(text).values())


def _max_consonant_run(text: str) -> int:
    best = run = 0
    for char in text:
        run = run + 1 if char.isalpha() and char not in VOWELS else 0
        best = max(best, run)
    return best


def extract_features(domain: str) -> dict | None:
    labels = [label for label in domain.strip().lower().rstrip(".").split(".") if label]
    if len(labels) < 2 or labels[-1] == "arpa":
        return None
    sld, subdomains, suffix = _registrable(labels)
    core = sld.replace("-", "")
    letters = [char for char in core if char.isalpha()]
    digits = sum(char.isdigit() for char in core)
    return {
        "sld": sld,
        "tld": suffix,
        "length": len(sld),
        "entropy": round(_entropy(core), 3),
        "digit_ratio": round(digits / len(core), 3) if core else 0.0,
        "vowel_ratio": round(sum(c in VOWELS for c in letters) / len(letters), 3) if letters else 0.0,
        "consonant_run": _max_consonant_run(core),
        "hyphens": sld.count("-"),
        "keywords_sld": [kw for kw in KEYWORDS if kw in sld],
        "keywords_sub": [kw for kw in KEYWORDS if any(kw in sub for sub in subdomains)],
        "suspicious_tld": suffix in SUSPICIOUS_TLDS,
    }


def _clamp(value: float, high: float = 1.5) -> float:
    return max(0.0, min(high, value))


def _contributions(f: dict) -> list[tuple[float, str]]:
    kw_sld, kw_sub = f["keywords_sld"][:2], f["keywords_sub"][:2]
    items = [
        (1.6 * _clamp(f["entropy"] - 2.8), f"High entropy ({f['entropy']:.2f} bits/char)"),
        (1.2 * _clamp((f["length"] - 10) / 8), f"Long label ({f['length']} chars)"),
        (2.2 * _clamp(f["digit_ratio"] / 0.3), f"Digits mixed into name ({f['digit_ratio']:.0%})"),
        (1.5 * _clamp((0.30 - f["vowel_ratio"]) / 0.15), f"Few vowels ({f['vowel_ratio']:.0%})"),
        (0.8 * _clamp((f["consonant_run"] - 3) / 3), f"Long consonant run ({f['consonant_run']})"),
        (1.4 * len(kw_sld), f"Suspicious keywords: {', '.join(kw_sld)}"),
        (0.5 * len(kw_sub), f"Keywords in subdomain: {', '.join(kw_sub)}"),
        (0.6 * min(f["hyphens"], 3), f"Many hyphens ({f['hyphens']})"),
        (1.0 if f["suspicious_tld"] else 0.0, f"High-risk TLD (.{f['tld']})"),
    ]
    return [(weight, reason) for weight, reason in items if weight > 0]


def _label(score: float) -> str:
    if score >= MALICIOUS_AT:
        return "malicious"
    if score >= SUSPICIOUS_AT:
        return "suspicious"
    return "benign"


def score_domain(domain: str) -> MlResult:
    features = extract_features(domain)
    if features is None:
        return MlResult(score=0.0, label="benign")
    contributions = _contributions(features)
    z = BIAS + sum(weight for weight, _ in contributions)
    score = round(1 / (1 + math.exp(-z)), 4)
    reasons = tuple(
        reason for weight, reason in sorted(contributions, reverse=True) if weight >= MIN_REASON_WEIGHT
    )
    return MlResult(score=score, label=_label(score), reasons=reasons, features=features)
