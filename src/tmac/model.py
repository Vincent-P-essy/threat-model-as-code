"""The model: what a system is made of, in YAML.

A threat model is only useful if it is *specific*. "The API could be attacked"
generates nothing actionable; "the payments API reads settlement instructions
from an SFTP drop that crosses the vendor trust boundary, unauthenticated" tells
you what to build. So the schema forces the details that generate real threats:
what crosses which boundary, what data classification it carries, and whether
the flow is authenticated.

Everything that cannot be inferred is required. A data flow with no classified
data and no boundary crossing generates almost nothing, and that is correct —
the model should be quiet about the parts of a system that do not matter.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class ModelError(ValueError):
    """Raised when a model is malformed. Always names the offending element."""


class ElementKind(str, enum.Enum):
    """The four DFD element kinds. STRIDE applies differently to each."""

    PROCESS = "process"
    STORE = "store"
    FLOW = "flow"
    EXTERNAL = "external"

    @property
    def label(self) -> str:
        return {
            ElementKind.PROCESS: "Process",
            ElementKind.STORE: "Data store",
            ElementKind.FLOW: "Data flow",
            ElementKind.EXTERNAL: "External entity",
        }[self]


class Classification(str, enum.Enum):
    """Data sensitivity. Drives impact scoring, so it is not decorative."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    PII = "pii"
    SECRET = "secret"

    @property
    def impact_weight(self) -> int:
        return {
            Classification.PUBLIC: 1,
            Classification.INTERNAL: 2,
            Classification.CONFIDENTIAL: 3,
            Classification.PII: 4,
            Classification.SECRET: 5,
        }[self]


@dataclass(frozen=True)
class TrustBoundary:
    """A line in the system where the level of trust changes.

    Boundaries are where threats live. A flow that stays inside one is far less
    interesting than one that crosses out of it, and the enumerator weights
    accordingly.
    """

    id: str
    name: str
    description: str = ""


@dataclass(frozen=True)
class Element:
    """A node in the data-flow diagram."""

    id: str
    kind: ElementKind
    name: str
    description: str = ""
    boundary: str | None = None
    data: tuple[Classification, ...] = ()
    technologies: tuple[str, ...] = ()
    #: Mitigation ids already implemented, checked against the controls library.
    controls: tuple[str, ...] = ()
    #: Threat ids explicitly accepted, with a reason. Accepting a risk is a
    #: legitimate decision; doing it silently is not, so the reason is required.
    accepted: dict[str, str] = field(default_factory=dict)

    @property
    def max_classification(self) -> Classification:
        return max(self.data, key=lambda c: c.impact_weight) if self.data else Classification.PUBLIC


@dataclass(frozen=True)
class Flow:
    """A directed edge: data moving from one element to another."""

    id: str
    name: str
    source: str
    target: str
    data: tuple[Classification, ...] = ()
    protocol: str = ""
    authenticated: bool = False
    encrypted: bool = False
    description: str = ""
    controls: tuple[str, ...] = ()
    accepted: dict[str, str] = field(default_factory=dict)

    @property
    def max_classification(self) -> Classification:
        return max(self.data, key=lambda c: c.impact_weight) if self.data else Classification.PUBLIC


@dataclass(frozen=True)
class Model:
    """A whole system."""

    name: str
    version: str
    description: str
    boundaries: tuple[TrustBoundary, ...]
    elements: tuple[Element, ...]
    flows: tuple[Flow, ...]
    owner: str = ""

    def element(self, element_id: str) -> Element | None:
        return next((e for e in self.elements if e.id == element_id), None)

    def boundary(self, boundary_id: str | None) -> TrustBoundary | None:
        if boundary_id is None:
            return None
        return next((b for b in self.boundaries if b.id == boundary_id), None)

    def crosses_boundary(self, flow: Flow) -> bool:
        """True when a flow moves between two different trust zones.

        A flow touching an element with no boundary counts as crossing: an
        unplaced element is either outside every zone or an oversight, and both
        deserve the threats.
        """
        source, target = self.element(flow.source), self.element(flow.target)
        if source is None or target is None:
            return True
        if source.boundary is None or target.boundary is None:
            return True
        return source.boundary != target.boundary

    def flows_touching(self, element_id: str) -> list[Flow]:
        return [f for f in self.flows if element_id in (f.source, f.target)]

    def stats(self) -> dict[str, int]:
        counts = {kind.value: 0 for kind in ElementKind}
        for element in self.elements:
            counts[element.kind.value] += 1
        counts["flow"] = len(self.flows)
        counts["boundaries"] = len(self.boundaries)
        counts["crossing_flows"] = sum(1 for f in self.flows if self.crosses_boundary(f))
        return counts


def _classifications(raw: Any, where: str) -> tuple[Classification, ...]:
    if raw is None:
        return ()
    if isinstance(raw, str):
        raw = [raw]
    out = []
    for item in raw:
        try:
            out.append(Classification(str(item).lower()))
        except ValueError:
            raise ModelError(
                f"{where}: unknown data classification {item!r}; expected one of "
                f"{', '.join(c.value for c in Classification)}"
            ) from None
    return tuple(out)


def _strings(raw: Any) -> tuple[str, ...]:
    if raw is None:
        return ()
    if isinstance(raw, str):
        return (raw,)
    return tuple(str(item) for item in raw)


def _accepted(raw: Any, where: str) -> dict[str, str]:
    if not raw:
        return {}
    if not isinstance(raw, dict):
        raise ModelError(
            f"{where}: 'accepted' must map threat id to a reason - accepting a risk "
            "without recording why is how it stops being a decision"
        )
    for threat_id, reason in raw.items():
        if not str(reason).strip():
            raise ModelError(f"{where}: accepted threat {threat_id!r} has no reason")
    return {str(k): str(v) for k, v in raw.items()}


def load(path: str | Path) -> Model:
    """Parse and validate a model file."""
    source = Path(path)
    if not source.exists():
        raise ModelError(f"model file not found: {source}")
    try:
        data = yaml.safe_load(source.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ModelError(f"{source.name}: invalid YAML: {exc}") from None
    if not isinstance(data, dict):
        raise ModelError(f"{source.name}: top level must be a mapping")
    return parse(data, source.name)


def parse(data: dict[str, Any], where: str = "model") -> Model:
    for key in ("name", "elements"):
        if key not in data:
            raise ModelError(f"{where}: missing required key {key!r}")

    boundaries = tuple(
        TrustBoundary(
            id=str(b["id"]),
            name=str(b.get("name", b["id"])),
            description=str(b.get("description", "")).strip(),
        )
        for b in (data.get("boundaries") or [])
    )
    boundary_ids = {b.id for b in boundaries}

    elements: list[Element] = []
    for raw in data.get("elements") or []:
        if "id" not in raw:
            raise ModelError(f"{where}: an element has no id")
        element_where = f"{where} element {raw['id']!r}"
        try:
            kind = ElementKind(str(raw.get("kind", "process")).lower())
        except ValueError:
            raise ModelError(
                f"{element_where}: unknown kind {raw.get('kind')!r}; expected one of "
                f"{', '.join(k.value for k in ElementKind)}"
            ) from None

        boundary = raw.get("boundary")
        if boundary is not None and str(boundary) not in boundary_ids:
            raise ModelError(
                f"{element_where}: references undeclared boundary {boundary!r}. "
                f"Declared: {', '.join(sorted(boundary_ids)) or 'none'}"
            )

        elements.append(
            Element(
                id=str(raw["id"]),
                kind=kind,
                name=str(raw.get("name", raw["id"])),
                description=str(raw.get("description", "")).strip(),
                boundary=str(boundary) if boundary is not None else None,
                data=_classifications(raw.get("data"), element_where),
                technologies=_strings(raw.get("technologies")),
                controls=_strings(raw.get("controls")),
                accepted=_accepted(raw.get("accepted"), element_where),
            )
        )

    element_ids = {e.id for e in elements}
    if len(element_ids) != len(elements):
        seen, dupes = set(), set()
        for element in elements:
            (dupes if element.id in seen else seen).add(element.id)
        raise ModelError(f"{where}: duplicate element id(s): {', '.join(sorted(dupes))}")

    flows: list[Flow] = []
    for raw in data.get("flows") or []:
        for key in ("id", "source", "target"):
            if key not in raw:
                raise ModelError(f"{where}: a flow is missing {key!r}")
        flow_where = f"{where} flow {raw['id']!r}"
        for end in ("source", "target"):
            if str(raw[end]) not in element_ids:
                raise ModelError(
                    f"{flow_where}: {end} {raw[end]!r} is not a declared element"
                )
        flows.append(
            Flow(
                id=str(raw["id"]),
                name=str(raw.get("name", raw["id"])),
                source=str(raw["source"]),
                target=str(raw["target"]),
                data=_classifications(raw.get("data"), flow_where),
                protocol=str(raw.get("protocol", "")),
                authenticated=bool(raw.get("authenticated", False)),
                encrypted=bool(raw.get("encrypted", False)),
                description=str(raw.get("description", "")).strip(),
                controls=_strings(raw.get("controls")),
                accepted=_accepted(raw.get("accepted"), flow_where),
            )
        )

    flow_ids = [f.id for f in flows]
    if len(set(flow_ids)) != len(flow_ids):
        raise ModelError(f"{where}: duplicate flow ids")

    return Model(
        name=str(data["name"]),
        version=str(data.get("version", "0.1")),
        description=str(data.get("description", "")).strip(),
        owner=str(data.get("owner", "")),
        boundaries=boundaries,
        elements=tuple(elements),
        flows=tuple(flows),
    )
