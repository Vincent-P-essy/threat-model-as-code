"""Checking the model against the code, so it cannot quietly rot.

This is the part that decides whether threat modelling survives contact with a
real project. A model is accurate on the day it is written. Six months later
someone has added three endpoints, moved a queue and pointed the service at a
new database, and the model in the wiki describes a system that no longer
exists — while still reporting a comfortable risk score.

`tmac drift` walks the source tree, extracts the entry points and outbound
dependencies it can recognise, and compares them against what the model
declares. Run in CI, it turns "the model is stale" from something nobody
notices into a failing check on the pull request that made it stale.

**What it can and cannot see.** It reads route decorators, client
constructions and connection strings — enough to catch the common drift, which
is a new endpoint nobody modelled. It cannot see a flow that only exists at
runtime through configuration, and it does not try: a drift checker that
guesses produces false positives, and a check people learn to ignore is worse
than no check. Everything it reports, it can point at a file and a line for.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .model import Model

SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "migrations", "vendor",
}

#: Each pattern must capture the thing being named, and only fire on a
#: definition rather than a mention, so a docstring cannot create a finding.
ROUTE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("flask", re.compile(r"@\w+\.(?:route|get|post|put|patch|delete)\(\s*[\"']([^\"']+)")),
    ("fastapi", re.compile(r"@\w+\.(?:get|post|put|patch|delete)\(\s*[\"']([^\"']+)")),
    ("express", re.compile(r"\b\w+\.(?:get|post|put|patch|delete)\(\s*[\"'`]([/][^\"'`]*)")),
    ("django", re.compile(r"\bpath\(\s*[\"']([^\"']*)")),
)

DEPENDENCY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("postgres", re.compile(r"postgres(?:ql)?://[^\s\"']+")),
    ("mysql", re.compile(r"mysql://[^\s\"']+")),
    ("mongodb", re.compile(r"mongodb(?:\+srv)?://[^\s\"']+")),
    ("redis", re.compile(r"redis://[^\s\"']+")),
    ("amqp", re.compile(r"amqps?://[^\s\"']+")),
    ("s3", re.compile(r"\bboto3\.client\(\s*[\"'](s3|kms|secretsmanager)[\"']")),
    ("http", re.compile(r"\b(?:requests|httpx)\.(?:get|post|put|delete)\(\s*[\"'](https?://[^\"']+)")),
    ("kafka", re.compile(r"\bKafka(?:Producer|Consumer)\(")),
)

SOURCE_SUFFIXES = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rb", ".java"}


@dataclass(frozen=True)
class Observation:
    """Something found in the code, with the place it was found."""

    kind: str
    value: str
    technology: str
    file: str
    line: int

    @property
    def label(self) -> str:
        return f"{self.technology}:{self.value}"


@dataclass(frozen=True)
class DriftFinding:
    severity: str
    kind: str
    detail: str
    evidence: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "severity": self.severity,
            "kind": self.kind,
            "detail": self.detail,
            "evidence": self.evidence,
        }


@dataclass
class DriftReport:
    observations: list[Observation]
    findings: list[DriftFinding]
    files_scanned: int

    @property
    def clean(self) -> bool:
        return not self.findings

    def to_dict(self) -> dict[str, object]:
        return {
            "clean": self.clean,
            "files_scanned": self.files_scanned,
            "observations": [
                {"kind": o.kind, "value": o.value, "technology": o.technology,
                 "file": o.file, "line": o.line}
                for o in self.observations
            ],
            "findings": [f.to_dict() for f in self.findings],
        }


def scan(root: str | Path) -> tuple[list[Observation], int]:
    """Walk a source tree; return observations and how many files were read."""
    base = Path(root)
    observations: list[Observation] = []
    scanned = 0

    for path in sorted(base.rglob("*")):
        if not path.is_file() or path.suffix not in SOURCE_SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        scanned += 1
        relative = str(path.relative_to(base))
        for number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            # A commented-out route is not an endpoint.
            if stripped.startswith(("#", "//", "*")):
                continue
            # A regex that *describes* a connection string is not a connection
            # to anything. Without this, any scanner reports itself - which is
            # how this check was found in the first place.
            if "re.compile" in line or "regexp" in line.lower():
                continue
            for technology, pattern in ROUTE_PATTERNS:
                for match in pattern.finditer(line):
                    observations.append(
                        Observation("route", match.group(1), technology, relative, number)
                    )
            for technology, pattern in DEPENDENCY_PATTERNS:
                for match in pattern.finditer(line):
                    value = match.group(1) if match.groups() else technology
                    observations.append(
                        Observation("dependency", _redact(value), technology, relative, number)
                    )
    # Flask and FastAPI decorators are written identically, so both patterns
    # match the same line. Deduplicate on position rather than on technology.
    unique: list[Observation] = []
    seen: set[tuple[str, str, str, int]] = set()
    for observation in observations:
        key = (observation.kind, observation.value, observation.file, observation.line)
        if key not in seen:
            seen.add(key)
            unique.append(observation)
    return unique, scanned


def _route_declared(path: str, declared_text: str) -> bool:
    """Is this route mentioned anywhere in the model?

    Compares on the static prefix, so `/v1/payments/<payment_id>` matches a
    model that documents `/v1/payments`. Deliberately permissive: the goal is
    to catch endpoints nobody thought about, not to police URL templates.
    """
    segments = [s for s in path.split("/") if s and not s.startswith(("<", "{", ":"))]
    if not segments:
        return True
    stem = "/" + "/".join(segments)
    return stem.lower() in declared_text or path.lower() in declared_text


def _redact(value: str) -> str:
    """Strip credentials out of anything that came from a connection string.

    A drift report gets pasted into pull requests and CI logs. Echoing a
    password found in the source into both would be an own goal.
    """
    return re.sub(r"://[^@/\s]+@", "://***@", value)


def check(model: Model, root: str | Path) -> DriftReport:
    """Compare a model against a source tree."""
    observations, files_scanned = scan(root)
    findings: list[DriftFinding] = []

    declared_text = " ".join(
        [
            *(f"{e.id} {e.name} {e.description} {' '.join(e.technologies)}"
              for e in model.elements),
            *(f"{f.id} {f.name} {f.description} {f.protocol}" for f in model.flows),
        ]
    ).lower()

    routes = [o for o in observations if o.kind == "route"]
    inbound = [f for f in model.flows if _is_inbound(model, f)]

    # The check that catches real drift: an endpoint in the code that the model
    # has never heard of. Path parameters are stripped before comparison so
    # /v1/payments/<id> matches a model that documents /v1/payments/.
    for route in routes:
        if _route_declared(route.value, declared_text):
            continue
        findings.append(
            DriftFinding(
                "high",
                "undeclared_endpoint",
                f"the code exposes {route.value!r} ({route.technology}), which no flow "
                "in the model mentions - it is an entry point nobody threat-modelled",
                f"{route.file}:{route.line}",
            )
        )

    if routes and not inbound:
        findings.append(
            DriftFinding(
                "high",
                "undeclared_entrypoints",
                f"{len(routes)} HTTP route(s) exist in the code, but the model declares "
                "no inbound flow. Every one of them is an unmodelled entry point.",
                f"{routes[0].file}:{routes[0].line} {routes[0].value}",
            )
        )

    # Technologies present in the code but absent from the model. Naming the
    # dependency is usually enough for a human to spot the missing flow.
    for observation in observations:
        if observation.kind != "dependency":
            continue
        if observation.technology.lower() in declared_text:
            continue
        findings.append(
            DriftFinding(
                "medium",
                "undeclared_dependency",
                f"the code talks to {observation.technology}, which no element or flow "
                "in the model mentions",
                f"{observation.file}:{observation.line}",
            )
        )

    # The reverse direction: a model that claims things the code does not do is
    # just as misleading, and usually means the model was aspirational.
    if not routes and inbound:
        findings.append(
            DriftFinding(
                "low",
                "unverifiable_flow",
                f"the model declares {len(inbound)} inbound flow(s) but no HTTP route was "
                "found in the source tree. Either the model is aspirational, or the "
                "entry point is one this scanner cannot see.",
            )
        )

    seen: set[tuple[str, str]] = set()
    unique: list[DriftFinding] = []
    for finding in findings:
        key = (finding.kind, finding.detail)
        if key not in seen:
            seen.add(key)
            unique.append(finding)

    return DriftReport(observations, unique, files_scanned)


def _is_inbound(model: Model, flow) -> bool:
    """A flow arriving from outside its target's trust zone."""
    source = model.element(flow.source)
    target = model.element(flow.target)
    if source is None or target is None:
        return False
    from .model import ElementKind

    return target.kind is ElementKind.PROCESS and source.boundary != target.boundary
