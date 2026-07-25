"""Enumeration and scoring: from a model to a ranked, actionable list.

Scoring exists to answer one question — what do we fix first — so it is
deliberately simple and fully explainable. Every number a threat carries can be
traced to a property of the model:

- **Impact** starts at the rule's base and is raised to the weight of the most
  sensitive data involved. A flaw touching secrets is worse than the same flaw
  touching public data, whatever the rule says.
- **Likelihood** starts at the rule's base and rises when the model says the
  attack is easier: the flow crosses a trust boundary, or nothing authenticates it.
- **Residual** applies the controls the model declares. Stacked controls have
  diminishing returns and are capped, because three partial mitigations do not
  make a threat disappear and a model that lets them is a model people will game.

Inherent and residual are both reported. Inherent alone ignores the work already
done; residual alone hides how much is riding on a single control.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum

from .model import Element, ElementKind, Flow, Model
from .stride import CONTROLS, Rule, Stride, applicable

#: Ceiling on stacked control credit. Three partial mitigations are not perfect
#: security, and without a cap a model can be made to score zero by listing
#: every control in the library.
MAX_COMBINED_REDUCTION = 0.85


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 3, Severity.HIGH: 2, Severity.MEDIUM: 1, Severity.LOW: 0
        }[self]


def band(score: int) -> Severity:
    """Risk score (1-25) to a severity band.

    The thresholds are deliberately high. With impact tracking data
    classification, a boundary-crossing flow carrying PII reaches 16 without
    anything being especially wrong with it — so a 15-point critical threshold
    paints two thirds of a realistic model red, and a report where everything
    is critical ranks nothing. Critical here means both dimensions are at or
    near the top.
    """
    if score >= 20:
        return Severity.CRITICAL
    if score >= 12:
        return Severity.HIGH
    if score >= 6:
        return Severity.MEDIUM
    return Severity.LOW


def _clamp(value: float) -> int:
    return max(1, min(5, int(round(value))))


@dataclass(frozen=True)
class Threat:
    """One enumerated threat against one element or flow."""

    id: str
    rule: Rule
    subject_id: str
    subject_name: str
    subject_kind: ElementKind
    likelihood: int
    impact: int
    residual_likelihood: int
    residual_impact: int
    applied_controls: tuple[str, ...]
    missing_controls: tuple[str, ...]
    accepted_reason: str | None = None
    why: tuple[str, ...] = ()

    @property
    def category(self) -> Stride:
        return self.rule.category

    @property
    def inherent_risk(self) -> int:
        return self.likelihood * self.impact

    @property
    def residual_risk(self) -> int:
        return self.residual_likelihood * self.residual_impact

    @property
    def severity(self) -> Severity:
        return band(self.residual_risk)

    @property
    def inherent_severity(self) -> Severity:
        return band(self.inherent_risk)

    @property
    def mitigated(self) -> bool:
        return bool(self.applied_controls)

    @property
    def accepted(self) -> bool:
        return self.accepted_reason is not None

    @property
    def open(self) -> bool:
        """Needs work: not accepted, and still above the low band."""
        return not self.accepted and self.severity is not Severity.LOW

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "rule": self.rule.id,
            "category": self.category.value,
            "violates": self.category.violates,
            "title": self.rule.title,
            "description": self.rule.description,
            "subject": {
                "id": self.subject_id,
                "name": self.subject_name,
                "kind": self.subject_kind.value,
            },
            "inherent": {
                "likelihood": self.likelihood,
                "impact": self.impact,
                "risk": self.inherent_risk,
                "severity": self.inherent_severity.value,
            },
            "residual": {
                "likelihood": self.residual_likelihood,
                "impact": self.residual_impact,
                "risk": self.residual_risk,
                "severity": self.severity.value,
            },
            "controls_applied": list(self.applied_controls),
            "controls_missing": list(self.missing_controls),
            "accepted": self.accepted_reason,
            "why": list(self.why),
            "references": list(self.rule.references),
        }


def _score(subject: Element | Flow, rule: Rule, model: Model) -> tuple[int, int, list[str]]:
    """Inherent likelihood and impact, plus the reasons they moved."""
    likelihood = float(rule.base_likelihood)
    impact = float(rule.base_impact)
    why: list[str] = []

    weight = subject.max_classification.impact_weight
    if weight > impact:
        impact = weight
        why.append(f"impact raised to {weight} by {subject.max_classification.value} data")

    if isinstance(subject, Flow):
        if model.crosses_boundary(subject):
            likelihood += 1
            why.append("crosses a trust boundary")
        if not subject.authenticated:
            likelihood += 1
            why.append("no authentication declared")
        if not subject.encrypted and weight >= 3:
            impact += 1
            why.append("sensitive data unencrypted in transit")
    else:
        exposed = [f for f in model.flows_touching(subject.id) if model.crosses_boundary(f)]
        if exposed:
            likelihood += 1
            why.append(f"reachable across a boundary via {len(exposed)} flow(s)")

    return _clamp(likelihood), _clamp(impact), why


def _residual(
    likelihood: int, impact: int, rule: Rule, declared: tuple[str, ...]
) -> tuple[int, int, list[str], list[str]]:
    """Apply declared controls, with capped stacking."""
    relevant = [
        control_id
        for control_id in declared
        if control_id in CONTROLS and rule.category in CONTROLS[control_id].addresses
    ]
    missing = [c for c in rule.mitigations if c not in declared]

    if not relevant:
        return likelihood, impact, [], missing

    remaining = 1.0
    for control_id in relevant:
        remaining *= 1 - CONTROLS[control_id].likelihood_reduction
    reduction = min(1 - remaining, MAX_COMBINED_REDUCTION)

    residual_likelihood = max(1, math.ceil(likelihood * (1 - reduction)))

    # Confidentiality controls reduce what an attacker gets, not just their odds.
    residual_impact = impact
    if rule.category is Stride.INFO_DISCLOSURE and {
        "tokenisation", "field_encryption", "encryption_at_rest"
    } & set(relevant):
        residual_impact = max(1, impact - 1)

    return residual_likelihood, residual_impact, relevant, missing


def enumerate_threats(model: Model) -> list[Threat]:
    """Enumerate every applicable threat, ranked by residual risk."""
    threats: list[Threat] = []

    for subject in (*model.elements, *model.flows):
        kind = ElementKind.FLOW if isinstance(subject, Flow) else subject.kind
        for rule in applicable(subject, model):
            likelihood, impact, why = _score(subject, rule, model)
            res_l, res_i, applied, missing = _residual(
                likelihood, impact, rule, subject.controls
            )
            threats.append(
                Threat(
                    id=f"{rule.id}@{subject.id}",
                    rule=rule,
                    subject_id=subject.id,
                    subject_name=subject.name,
                    subject_kind=kind,
                    likelihood=likelihood,
                    impact=impact,
                    residual_likelihood=res_l,
                    residual_impact=res_i,
                    applied_controls=tuple(applied),
                    missing_controls=tuple(missing),
                    accepted_reason=subject.accepted.get(rule.id),
                    why=tuple(why),
                )
            )

    threats.sort(key=lambda t: (-t.residual_risk, -t.inherent_risk, t.id))
    return threats


@dataclass(frozen=True)
class Summary:
    total: int
    open: int
    accepted: int
    mitigated: int
    by_severity: dict[Severity, int]
    by_category: dict[Stride, int]
    inherent_total: int
    residual_total: int

    @property
    def risk_reduction(self) -> float:
        """Share of inherent risk removed by declared controls."""
        if not self.inherent_total:
            return 0.0
        return 1 - (self.residual_total / self.inherent_total)

    def to_dict(self) -> dict[str, object]:
        return {
            "total": self.total,
            "open": self.open,
            "accepted": self.accepted,
            "mitigated": self.mitigated,
            "by_severity": {s.value: n for s, n in self.by_severity.items()},
            "by_category": {c.value: n for c, n in self.by_category.items()},
            "inherent_risk_total": self.inherent_total,
            "residual_risk_total": self.residual_total,
            "risk_reduction": round(self.risk_reduction, 3),
        }


def summarise(threats: list[Threat]) -> Summary:
    by_severity = {severity: 0 for severity in Severity}
    by_category = {category: 0 for category in Stride}
    for threat in threats:
        if not threat.accepted:
            by_severity[threat.severity] += 1
        by_category[threat.category] += 1

    return Summary(
        total=len(threats),
        open=sum(1 for t in threats if t.open),
        accepted=sum(1 for t in threats if t.accepted),
        mitigated=sum(1 for t in threats if t.mitigated),
        by_severity=by_severity,
        by_category=by_category,
        inherent_total=sum(t.inherent_risk for t in threats),
        residual_total=sum(t.residual_risk for t in threats if not t.accepted),
    )
