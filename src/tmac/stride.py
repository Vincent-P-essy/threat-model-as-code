"""STRIDE enumeration, and the controls that answer it.

Two things separate this from a checklist generator.

**Rules are conditional.** A rule that fires on every process produces a
hundred identical findings and teaches the team to skim. Each rule here has a
predicate over the actual model — does this flow cross a boundary, is it
authenticated, does it carry PII — so a threat appears when the model says the
conditions for it exist, and stays quiet otherwise.

**Every threat names the controls that answer it.** A threat with no mitigation
is a complaint. Each rule lists control ids from :data:`CONTROLS`, and a model
that declares one of them gets credit for it in the residual score — which is
what makes the same model worth re-running after the work is done.

Rules cite CAPEC and CWE where a public identifier exists, so a finding can be
traced to something outside this repository.
"""

from __future__ import annotations

import enum
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .model import Classification, Element, ElementKind, Flow, Model


class Stride(str, enum.Enum):
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFO_DISCLOSURE = "information_disclosure"
    DOS = "denial_of_service"
    ELEVATION = "elevation_of_privilege"

    @property
    def label(self) -> str:
        return {
            Stride.SPOOFING: "Spoofing",
            Stride.TAMPERING: "Tampering",
            Stride.REPUDIATION: "Repudiation",
            Stride.INFO_DISCLOSURE: "Information disclosure",
            Stride.DOS: "Denial of service",
            Stride.ELEVATION: "Elevation of privilege",
        }[self]

    @property
    def violates(self) -> str:
        return {
            Stride.SPOOFING: "authentication",
            Stride.TAMPERING: "integrity",
            Stride.REPUDIATION: "non-repudiation",
            Stride.INFO_DISCLOSURE: "confidentiality",
            Stride.DOS: "availability",
            Stride.ELEVATION: "authorisation",
        }[self]


@dataclass(frozen=True)
class Control:
    """A mitigation the model can declare as implemented."""

    id: str
    name: str
    description: str
    addresses: tuple[Stride, ...]
    #: How much declaring this control reduces likelihood, 0..1.
    likelihood_reduction: float = 0.5
    references: tuple[str, ...] = ()


CONTROLS: dict[str, Control] = {
    c.id: c
    for c in (
        Control("mtls", "Mutual TLS", "Both ends present certificates; neither is anonymous.",
                (Stride.SPOOFING, Stride.TAMPERING, Stride.INFO_DISCLOSURE), 0.7,
                ("NIST SP 800-52",)),
        Control("tls", "TLS in transit", "Transport encryption with certificate validation.",
                (Stride.TAMPERING, Stride.INFO_DISCLOSURE), 0.6),
        Control("oauth2", "OAuth 2.0 / OIDC", "Delegated authentication with short-lived tokens.",
                (Stride.SPOOFING, Stride.ELEVATION), 0.6),
        Control("mfa", "Multi-factor authentication", "A second factor on human authentication.",
                (Stride.SPOOFING,), 0.7),
        Control("rbac", "Role-based access control",
                "Permissions granted by role, denied by default.",
                (Stride.ELEVATION, Stride.INFO_DISCLOSURE), 0.6),
        Control("input_validation", "Input validation",
                "Schema validation and canonicalisation at the boundary.",
                (Stride.TAMPERING, Stride.ELEVATION), 0.6, ("CWE-20",)),
        Control("parameterised_queries", "Parameterised queries",
                "No string-built SQL anywhere.", (Stride.TAMPERING, Stride.ELEVATION), 0.8,
                ("CWE-89",)),
        Control("output_encoding", "Output encoding",
                "Context-aware escaping on every rendered value.", (Stride.TAMPERING,), 0.7,
                ("CWE-79",)),
        Control("audit_log", "Tamper-evident audit log",
                "Append-only, signed, externally anchored.", (Stride.REPUDIATION,), 0.8),
        Control("request_signing", "Request signing",
                "Each request signed by the caller; replay-protected.",
                (Stride.SPOOFING, Stride.TAMPERING, Stride.REPUDIATION), 0.7),
        Control("encryption_at_rest", "Encryption at rest",
                "Storage-level or field-level encryption with managed keys.",
                (Stride.INFO_DISCLOSURE,), 0.5),
        Control("field_encryption", "Field-level encryption",
                "Sensitive fields encrypted individually, keys held elsewhere.",
                (Stride.INFO_DISCLOSURE,), 0.7),
        Control("tokenisation", "Tokenisation",
                "Sensitive values replaced by tokens; the vault holds the mapping.",
                (Stride.INFO_DISCLOSURE,), 0.8),
        Control("rate_limit", "Rate limiting", "Per-caller quotas with backpressure.",
                (Stride.DOS,), 0.6),
        Control("quota", "Resource quotas", "Bounded memory, connections and request size.",
                (Stride.DOS,), 0.5),
        Control("circuit_breaker", "Circuit breaker",
                "Fail fast when a dependency degrades.", (Stride.DOS,), 0.5),
        Control("secrets_manager", "Managed secrets",
                "Secrets from a vault, never from config or images.",
                (Stride.INFO_DISCLOSURE, Stride.ELEVATION), 0.6),
        Control("key_rotation", "Key rotation", "Scheduled rotation with overlap.",
                (Stride.INFO_DISCLOSURE, Stride.SPOOFING), 0.4),
        Control("least_privilege", "Least privilege",
                "Each component holds only the permissions it uses.",
                (Stride.ELEVATION,), 0.6),
        Control("network_segmentation", "Network segmentation",
                "Deny-by-default egress and ingress between zones.",
                (Stride.ELEVATION, Stride.INFO_DISCLOSURE), 0.5),
        Control("integrity_check", "Integrity verification",
                "Checksums or signatures verified before use.", (Stride.TAMPERING,), 0.7),
        Control("backup_restore", "Tested backups", "Restores exercised, not just taken.",
                (Stride.DOS,), 0.5),
        Control("dlp", "Egress data-loss prevention",
                "Outbound content inspected against classification.",
                (Stride.INFO_DISCLOSURE,), 0.4),
        Control("anomaly_detection", "Anomaly detection",
                "Behavioural baselining with alerting.",
                (Stride.SPOOFING, Stride.INFO_DISCLOSURE), 0.3),
    )
}


@dataclass(frozen=True)
class Rule:
    """One conditional threat."""

    id: str
    category: Stride
    applies_to: tuple[ElementKind, ...]
    title: str
    description: str
    mitigations: tuple[str, ...]
    base_likelihood: int = 3
    base_impact: int = 3
    references: tuple[str, ...] = ()
    condition: Callable[[Any, Model], bool] = lambda subject, model: True


def _flow(subject: Any) -> Flow | None:
    return subject if isinstance(subject, Flow) else None


def _sensitive(subject: Any) -> bool:
    return subject.max_classification.impact_weight >= Classification.CONFIDENTIAL.impact_weight


RULES: tuple[Rule, ...] = (
    # -- flows --------------------------------------------------------------
    Rule(
        "F-SPOOF-01", Stride.SPOOFING, (ElementKind.FLOW,),
        "Unauthenticated flow across a trust boundary",
        "The flow leaves its trust zone without authenticating either end, so any "
        "party able to reach the endpoint can impersonate the legitimate caller.",
        ("mtls", "oauth2", "request_signing"), 4, 4,
        ("CAPEC-94", "CWE-306"),
        lambda s, m: not s.authenticated and m.crosses_boundary(s),
    ),
    Rule(
        "F-TAMP-01", Stride.TAMPERING, (ElementKind.FLOW,),
        "Unencrypted flow carrying sensitive data",
        "Data crosses the network in the clear, so anyone on the path can read or "
        "modify it in transit.",
        ("tls", "mtls"), 3, 4, ("CAPEC-94", "CWE-319"),
        lambda s, m: not s.encrypted and _sensitive(s),
    ),
    Rule(
        "F-INFO-01", Stride.INFO_DISCLOSURE, (ElementKind.FLOW,),
        "Regulated data leaves its trust zone",
        "PII or secrets cross a boundary. Wherever they land inherits the "
        "obligations that came with them, including retention and erasure.",
        ("tokenisation", "field_encryption", "dlp"), 3, 5,
        ("GDPR Art. 32",),
        lambda s, m: m.crosses_boundary(s)
        and any(c in (Classification.PII, Classification.SECRET) for c in s.data),
    ),
    Rule(
        "F-REPU-01", Stride.REPUDIATION, (ElementKind.FLOW,),
        "State-changing flow without an audit record",
        "A caller can later deny having made the request, and the operator cannot "
        "prove otherwise.",
        ("audit_log", "request_signing"), 3, 3, ("CWE-778",),
        lambda s, m: m.crosses_boundary(s) and "audit_log" not in s.controls,
    ),
    Rule(
        "F-DOS-01", Stride.DOS, (ElementKind.FLOW,),
        "Externally reachable flow with no rate limit",
        "An unauthenticated caller can consume the downstream service's capacity.",
        ("rate_limit", "quota", "circuit_breaker"), 3, 3, ("CAPEC-125",),
        lambda s, m: not s.authenticated and m.crosses_boundary(s),
    ),
    Rule(
        "F-ELEV-01", Stride.ELEVATION, (ElementKind.FLOW,),
        "Inbound flow from a lower-trust zone into a privileged process",
        "Input arriving from outside is processed by a component with elevated "
        "rights; a parsing flaw becomes a privilege escalation.",
        ("input_validation", "least_privilege", "network_segmentation"), 3, 5,
        ("CWE-20",),
        lambda s, m: m.crosses_boundary(s)
        and (m.element(s.target).kind is ElementKind.PROCESS if m.element(s.target) else False),
    ),
    # -- processes ----------------------------------------------------------
    Rule(
        "P-SPOOF-01", Stride.SPOOFING, (ElementKind.PROCESS,),
        "Process accepts requests without authenticating the caller",
        "At least one inbound flow to this process is unauthenticated, so its "
        "callers are whoever can reach it.",
        ("oauth2", "mtls", "mfa"), 4, 4, ("CWE-306",),
        lambda s, m: any(
            not f.authenticated and f.target == s.id and m.crosses_boundary(f)
            for f in m.flows
        ),
    ),
    Rule(
        "P-TAMP-01", Stride.TAMPERING, (ElementKind.PROCESS,),
        "Untrusted input reaches application logic",
        "Input from outside the trust zone is parsed here. Injection, deserialisation "
        "and path traversal all land at this element.",
        ("input_validation", "parameterised_queries", "output_encoding"), 4, 4,
        ("CWE-20", "CWE-89", "CWE-79"),
        lambda s, m: any(f.target == s.id and m.crosses_boundary(f) for f in m.flows),
    ),
    Rule(
        "P-ELEV-01", Stride.ELEVATION, (ElementKind.PROCESS,),
        "Process handles data of mixed classification without documented authorisation",
        "The component sees several sensitivity levels, so a flaw in its "
        "authorisation logic exposes the most sensitive of them.",
        ("rbac", "least_privilege"), 3, 4, ("CWE-285",),
        lambda s, m: len(set(s.data)) > 1 and "rbac" not in s.controls,
    ),
    Rule(
        "P-INFO-01", Stride.INFO_DISCLOSURE, (ElementKind.PROCESS,),
        "Process holds secrets with no managed secret store declared",
        "Credentials in configuration, environment or images leak through logs, "
        "crash dumps and image layers.",
        ("secrets_manager", "key_rotation"), 3, 4, ("CWE-798",),
        lambda s, m: Classification.SECRET in s.data and "secrets_manager" not in s.controls,
    ),
    Rule(
        "P-DOS-01", Stride.DOS, (ElementKind.PROCESS,),
        "Single process on a critical path with no resilience control",
        "Every flow through this component stops when it does.",
        ("circuit_breaker", "quota", "rate_limit"), 2, 4, (),
        lambda s, m: len(m.flows_touching(s.id)) >= 3,
    ),
    Rule(
        "P-REPU-01", Stride.REPUDIATION, (ElementKind.PROCESS,),
        "Privileged actions are not attributable",
        "The process acts on sensitive data with no audit control declared, so "
        "there is no record of who did what.",
        ("audit_log",), 3, 3, ("CWE-778",),
        lambda s, m: _sensitive(s) and "audit_log" not in s.controls,
    ),
    # -- stores -------------------------------------------------------------
    Rule(
        "S-INFO-01", Stride.INFO_DISCLOSURE, (ElementKind.STORE,),
        "Sensitive data at rest without encryption declared",
        "A stolen backup, snapshot or disk image discloses the contents directly.",
        ("encryption_at_rest", "field_encryption", "tokenisation"), 3, 5,
        ("CWE-311", "GDPR Art. 32"),
        lambda s, m: _sensitive(s)
        and not {"encryption_at_rest", "field_encryption", "tokenisation"} & set(s.controls),
    ),
    Rule(
        "S-TAMP-01", Stride.TAMPERING, (ElementKind.STORE,),
        "Stored records can be modified without detection",
        "Nothing binds a record to its history, so an edit made directly in the "
        "store leaves no trace.",
        ("audit_log", "integrity_check"), 3, 4, ("CWE-345",),
        lambda s, m: _sensitive(s)
        and not {"audit_log", "integrity_check"} & set(s.controls),
    ),
    Rule(
        "S-ELEV-01", Stride.ELEVATION, (ElementKind.STORE,),
        "Store reachable from more than one trust zone",
        "A compromise in the least protected zone reaches the data directly.",
        ("network_segmentation", "rbac", "least_privilege"), 3, 4, (),
        lambda s, m: len({m.element(f.source).boundary
                          for f in m.flows if f.target == s.id and m.element(f.source)}) > 1,
    ),
    Rule(
        "S-DOS-01", Stride.DOS, (ElementKind.STORE,),
        "No tested restore path for a store on a critical flow",
        "Loss or ransomware encryption of this store stops the flows that depend "
        "on it, and an untested backup is a hypothesis.",
        ("backup_restore",), 2, 5, (),
        lambda s, m: "backup_restore" not in s.controls,
    ),
    Rule(
        "S-REPU-01", Stride.REPUDIATION, (ElementKind.STORE,),
        "Deletions and updates are not recorded",
        "Records can be removed with no evidence that they existed.",
        ("audit_log",), 3, 3, ("CWE-778",),
        lambda s, m: _sensitive(s) and "audit_log" not in s.controls,
    ),
    # -- external entities ---------------------------------------------------
    Rule(
        "E-SPOOF-01", Stride.SPOOFING, (ElementKind.EXTERNAL,),
        "External party identity is asserted, not verified",
        "The system takes the counterparty's word for who they are on at least one "
        "flow.",
        ("mtls", "oauth2", "request_signing"), 4, 4, ("CAPEC-151",),
        lambda s, m: any(
            not f.authenticated and f.source == s.id for f in m.flows
        ),
    ),
    Rule(
        "E-REPU-01", Stride.REPUDIATION, (ElementKind.EXTERNAL,),
        "Third-party instructions are not independently evidenced",
        "A counterparty can deny having sent an instruction and there is nothing "
        "signed to contradict them.",
        ("request_signing", "audit_log"), 3, 4, (),
        lambda s, m: any(f.source == s.id and _sensitive(f) for f in m.flows),
    ),
)


def applicable(subject: Element | Flow, model: Model) -> list[Rule]:
    """Rules whose kind and condition both match."""
    kind = ElementKind.FLOW if isinstance(subject, Flow) else subject.kind
    out = []
    for rule in RULES:
        if kind not in rule.applies_to:
            continue
        try:
            if rule.condition(subject, model):
                out.append(rule)
        except (AttributeError, TypeError):
            # A condition that cannot evaluate against this subject does not
            # fire. Better a missing threat than a crash mid-enumeration.
            continue
    return out


def controls_for(rule: Rule) -> list[Control]:
    return [CONTROLS[c] for c in rule.mitigations if c in CONTROLS]


def unknown_controls(model: Model) -> dict[str, list[str]]:
    """Controls declared in the model that are not in the library.

    A typo in a control id silently means "no mitigation", which quietly
    inflates the residual risk with no error anywhere. This surfaces it.
    """
    out: dict[str, list[str]] = {}
    for subject in (*model.elements, *model.flows):
        unknown = [c for c in subject.controls if c not in CONTROLS]
        if unknown:
            out[subject.id] = unknown
    return out
