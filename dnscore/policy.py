"""Pure policy evaluation: decides whether a query is allowed or blocked, and why.

Precedence: local zones > allow rules > block rules > threat feeds > ML detector.
"""
from __future__ import annotations

from collections.abc import Collection, Mapping
from dataclasses import dataclass

from .catalog import get_category, ml_severity
from .ml import MlResult, score_domain


@dataclass(frozen=True)
class Decision:
    action: str  # "allowed" | "blocked"
    category: str | None = None
    source: str | None = None  # "feed" | "policy" | "ml"
    severity: str | None = None
    confidence: float | None = None
    matched: str | None = None
    ml_score: float = 0.0

    @property
    def blocked(self) -> bool:
        return self.action == "blocked"


@dataclass(frozen=True)
class PolicySnapshot:
    enabled: frozenset[str]
    blocklist: Mapping[str, str]
    block_rules: Mapping[str, str]
    allow_rules: frozenset[str]
    local_zones: tuple[str, ...]
    ml_threshold: float = 0.85
    ml_auto_block: bool = True


def candidate_names(domain: str) -> tuple[str, ...]:
    """The name itself plus each parent domain, stopping before the bare TLD."""
    labels = domain.lower().rstrip(".").split(".")
    return tuple(".".join(labels[i:]) for i in range(max(len(labels) - 1, 1)))


def is_local(domain: str, zones: tuple[str, ...]) -> bool:
    name = domain.lower().rstrip(".")
    return any(name == zone or name.endswith("." + zone) for zone in zones)


def _first_match(names: tuple[str, ...], table: Collection[str]) -> str | None:
    return next((name for name in names if name in table), None)


def evaluate(snapshot: PolicySnapshot, domain: str, ml: MlResult | None = None) -> Decision:
    if is_local(domain, snapshot.local_zones):
        return Decision("allowed", matched="local-zone")
    names = candidate_names(domain)
    result = ml or score_domain(domain)

    allowed = _first_match(names, snapshot.allow_rules)
    if allowed:
        return Decision("allowed", source="policy", matched=allowed, ml_score=result.score)

    rule = _first_match(names, snapshot.block_rules)
    if rule:
        category = snapshot.block_rules[rule]
        return Decision("blocked", category, "policy", get_category(category).severity,
                        matched=rule, ml_score=result.score)

    listed = next(
        (n for n in names if n in snapshot.blocklist and snapshot.blocklist[n] in snapshot.enabled),
        None,
    )
    if listed:
        category = snapshot.blocklist[listed]
        return Decision("blocked", category, "feed", get_category(category).severity,
                        matched=listed, ml_score=result.score)

    if snapshot.ml_auto_block and "ml" in snapshot.enabled and result.score >= snapshot.ml_threshold:
        return Decision("blocked", "ml", "ml", ml_severity(result.score), confidence=result.score,
                        matched="ml-detector", ml_score=result.score)
    return Decision("allowed", ml_score=result.score)
