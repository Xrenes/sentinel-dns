"""Static metadata: blocklist categories, severities, detection sources and record types."""
from __future__ import annotations

from dataclasses import dataclass

SEVERITIES = ("critical", "high", "medium", "low")
SOURCE_LABELS = {"feed": "Threat Intel", "policy": "Policy Rule", "ml": "ML Detector"}
RECORD_TYPES = {
    "forward": ("A", "AAAA", "CNAME", "MX", "TXT", "NS"),
    "reverse": ("PTR", "NS"),
}
QUERY_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR", "SOA")


@dataclass(frozen=True)
class Category:
    key: str
    name: str
    color: str
    severity: str
    description: str
    feed: str
    demo_count: int = 0


CATEGORIES: tuple[Category, ...] = (
    Category("advertising", "Advertising", "#facc15", "low",
             "Ad networks and ad-serving domains", "StevenBlack Unified Hosts", 58_912),
    Category("tracking", "Tracking", "#22d3ee", "low",
             "Analytics, telemetry and behavioural trackers", "EasyPrivacy (Firebog)", 21_404),
    Category("social", "Social Media", "#c084fc", "low",
             "Social networks (lab policy category)", "StevenBlack · social", 3_118),
    Category("malware", "Malware", "#f87171", "high",
             "Malware distribution and command-and-control servers", "URLhaus via malware-filter", 18_233),
    Category("phishing", "Phishing", "#fb7185", "critical",
             "Credential-harvesting and fake login pages", "Phishing Army", 9_872),
    Category("crypto", "Cryptocurrency", "#fb923c", "medium",
             "In-browser crypto-mining and crypto scams", "NoCoin Filter List", 1_904),
    Category("adult", "Adult Content", "#f472b6", "medium",
             "Adult content (lab policy category)", "StevenBlack · porn", 46_551),
    Category("gaming", "Gaming", "#4ade80", "low",
             "Online gaming and gambling (lab policy category)", "StevenBlack · gambling", 4_219),
    Category("ml", "ML-Detected", "#a78bfa", "high",
             "Algorithmically generated domains flagged by the ML detector", "Sentinel ML Detector"),
    Category("other", "Other", "#d1d5db", "low",
             "Custom block rules created by administrators", "Custom rules"),
)

CATEGORY_BY_KEY = {category.key: category for category in CATEGORIES}
FEED_CATEGORIES = tuple(c.key for c in CATEGORIES if c.key not in ("ml", "other"))


def get_category(key: str | None) -> Category:
    return CATEGORY_BY_KEY.get(key or "other", CATEGORY_BY_KEY["other"])


def category_view(key: str | None) -> dict[str, str]:
    category = get_category(key)
    return {"key": category.key, "name": category.name, "color": category.color}


def ml_severity(confidence: float) -> str:
    if confidence >= 0.97:
        return "critical"
    if confidence >= 0.9:
        return "high"
    return "medium"
