"""Turning threats into work a development team will actually pick up.

A threat report is read once and archived. A backlog item gets estimated,
assigned and closed. The gap between the two is the reason most threat
modelling produces no change in the system, so this module closes it.

Two design choices do the work:

**Stories group by control, not by threat.** Eleven threats answered by
"add mutual TLS on the vendor boundary" are one piece of work, not eleven.
Emitting them separately guarantees the backlog is ignored.

**Acceptance criteria are executable-shaped.** "Ensure the endpoint is secure"
cannot be closed. "A request without a client certificate is rejected with 403,
and the rejection appears in the audit log" can be turned into a test, and a
reviewer can tell whether it passed.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from .engine import Severity, Threat
from .stride import CONTROLS, Control, Stride

#: Acceptance criteria per control. Written so each line is checkable by a test
#: or by looking at one specific thing, rather than by forming an opinion.
CRITERIA: dict[str, tuple[str, ...]] = {
    "mtls": (
        "a request presenting no client certificate is rejected with 403",
        "a request presenting a certificate signed by an untrusted CA is rejected",
        "the peer certificate subject appears in the request log",
    ),
    "tls": (
        "plaintext connections to the endpoint are refused, not upgraded",
        "the certificate chain is validated, and validation failure closes the connection",
        "TLS versions below 1.2 are refused",
    ),
    "oauth2": (
        "a request with no bearer token is rejected with 401",
        "a token with an expired `exp` is rejected",
        "a token whose audience is another service is rejected",
    ),
    "mfa": (
        "an account with a password alone cannot complete authentication",
        "second-factor enrolment is required before first privileged use",
    ),
    "rbac": (
        "a caller whose role lacks the permission receives 403, not 404 or 200",
        "the default for an unlisted permission is deny",
        "role assignments are readable from one place",
    ),
    "input_validation": (
        "input failing schema validation is rejected before any business logic runs",
        "the rejection message does not echo the offending value back",
        "validation runs on the server regardless of any client-side check",
    ),
    "parameterised_queries": (
        "no SQL string is built by concatenation or f-string anywhere in the module",
        "a test submits `'; DROP TABLE --` in each user-controlled field and asserts "
        "it is stored literally",
    ),
    "output_encoding": (
        "a stored value containing `<script>` renders as text, not markup",
        "encoding is chosen by output context (HTML, attribute, URL, JS)",
    ),
    "audit_log": (
        "every state-changing operation writes an entry naming actor, action, resource and outcome",
        "entries cannot be updated or deleted through the application",
        "a deleted or edited entry is detectable after the fact",
    ),
    "request_signing": (
        "a request with a missing or invalid signature is rejected",
        "a replayed request with a previously seen nonce is rejected",
        "clock skew beyond the accepted window is rejected",
    ),
    "encryption_at_rest": (
        "a snapshot or backup file taken from the volume does not contain readable records",
        "keys are held outside the database, in a managed store",
    ),
    "field_encryption": (
        "the sensitive column is unreadable in a raw SELECT",
        "decryption happens in the application, with keys fetched per-use",
    ),
    "tokenisation": (
        "the store contains tokens only; no code path writes the raw value",
        "detokenisation is a separate service with its own authorisation",
    ),
    "rate_limit": (
        "a caller exceeding the quota receives 429 with `Retry-After`",
        "the limit is per-caller, not global, so one client cannot starve the rest",
    ),
    "quota": (
        "request bodies above the configured size are rejected before being buffered",
        "connection and memory ceilings are set explicitly, not left to defaults",
    ),
    "circuit_breaker": (
        "when the dependency fails repeatedly, calls fail fast rather than queueing",
        "the breaker's state is exported as a metric",
    ),
    "secrets_manager": (
        "no secret appears in the repository, the image, or an environment variable dump",
        "the application fetches secrets at start-up from the vault and holds them in memory only",
    ),
    "key_rotation": (
        "a rotation can be completed with no downtime, using an overlap window",
        "material signed under the previous key still verifies after rotation",
    ),
    "least_privilege": (
        "the service account's permissions are enumerated and each one is used",
        "no wildcard permission remains in the policy",
    ),
    "network_segmentation": (
        "egress from the zone is deny-by-default with an explicit allowlist",
        "a host in the lower-trust zone cannot open a connection to the store",
    ),
    "integrity_check": (
        "content failing its checksum or signature is rejected before use",
        "the rejection is logged with the expected and actual values",
    ),
    "backup_restore": (
        "a restore has been performed into a clean environment within the last quarter",
        "the restore procedure and its measured duration are documented",
    ),
    "dlp": (
        "outbound payloads matching the sensitive-data patterns are blocked or quarantined",
        "the block is alerted, not only logged",
    ),
    "anomaly_detection": (
        "a baseline exists for the metric being watched",
        "an alert fires to a rota that is on call, not to a mailbox",
    ),
}

ROLE = {
    Stride.SPOOFING: "platform engineer",
    Stride.TAMPERING: "application developer",
    Stride.REPUDIATION: "compliance owner",
    Stride.INFO_DISCLOSURE: "data owner",
    Stride.DOS: "site reliability engineer",
    Stride.ELEVATION: "application developer",
}


@dataclass(frozen=True)
class Story:
    """One backlog item answering one control on one part of the system."""

    id: str
    control: Control
    subject_id: str
    subject_name: str
    role: str
    severity: Severity
    threats: tuple[Threat, ...]
    criteria: tuple[str, ...]

    @property
    def title(self) -> str:
        return f"{self.control.name} on {self.subject_name}"

    @property
    def points(self) -> int:
        """A rough size, so the item can enter a sprint without a meeting.

        Deliberately coarse. The value is that everything gets *a* number;
        pretending to more precision than this would be false.
        """
        base = {"critical": 8, "high": 5, "medium": 3, "low": 2}[self.severity.value]
        return base + (2 if len(self.threats) > 2 else 0)

    def render(self) -> str:
        threat_list = "\n".join(
            f"  - `{t.rule.id}` {t.rule.title} (residual {t.residual_risk}, {t.severity.value})"
            for t in self.threats
        )
        criteria = "\n".join(f"  - [ ] {c}" for c in self.criteria)
        refs = sorted({r for t in self.threats for r in t.rule.references})
        return (
            f"### {self.id} — {self.title}\n\n"
            f"**As a** {self.role}, **I want** {self.control.description.lower().rstrip('.')}, "
            f"**so that** {self.control.addresses[0].violates} of "
            f"`{self.subject_id}` no longer depends on nothing.\n\n"
            f"- **Severity**: {self.severity.value}\n"
            f"- **Estimate**: {self.points} points\n"
            f"- **Closes**:\n{threat_list}\n\n"
            f"**Acceptance criteria**\n{criteria}\n"
            + (f"\n**References**: {', '.join(refs)}\n" if refs else "")
        )


def generate(threats: list[Threat], *, include_accepted: bool = False) -> list[Story]:
    """Group open threats into deduplicated backlog items."""
    grouped: dict[tuple[str, str], list[Threat]] = defaultdict(list)

    for threat in threats:
        if threat.accepted and not include_accepted:
            continue
        if threat.severity is Severity.LOW:
            continue
        # The first missing control is the one to do first; listing every
        # alternative as its own story is how a backlog becomes noise.
        for control_id in threat.missing_controls[:1]:
            if control_id in CONTROLS:
                grouped[(control_id, threat.subject_id)].append(threat)

    stories: list[Story] = []
    for index, ((control_id, subject_id), items) in enumerate(
        sorted(
            grouped.items(),
            key=lambda kv: (-max(t.residual_risk for t in kv[1]), kv[0]),
        ),
        start=1,
    ):
        control = CONTROLS[control_id]
        worst = max(items, key=lambda t: t.residual_risk)
        stories.append(
            Story(
                id=f"SEC-{index:03d}",
                control=control,
                subject_id=subject_id,
                subject_name=items[0].subject_name,
                role=ROLE[worst.category],
                severity=worst.severity,
                threats=tuple(sorted(items, key=lambda t: -t.residual_risk)),
                criteria=CRITERIA.get(control_id, ("the control is implemented and tested",)),
            )
        )
    return stories


def render_backlog(stories: list[Story], model_name: str) -> str:
    total = sum(s.points for s in stories)
    lines = [
        f"# Security backlog — {model_name}",
        "",
        f"{len(stories)} items, {total} points. Generated from the threat model; "
        "regenerate after any change to it.",
        "",
    ]
    for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
        batch = [s for s in stories if s.severity is severity]
        if not batch:
            continue
        lines += [
            f"## {severity.value.title()} ({len(batch)} items, "
            f"{sum(s.points for s in batch)} points)",
            "",
        ]
        lines += [story.render() for story in batch]
    return "\n".join(lines)
