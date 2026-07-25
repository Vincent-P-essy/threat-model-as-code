"""Data-flow diagrams in Mermaid.

Generated rather than drawn, for one reason: a diagram maintained by hand
diverges from the model within a sprint, and then the picture in the wiki and
the threats in the report describe different systems.

Mermaid because GitHub renders it inline — the diagram lives in the pull request
that changes the model, which is the only place anyone will actually look at it.

Risk shading is optional and off by default. A diagram with everything coloured
red communicates nothing; `--risk` is for the review meeting, plain is for the
architecture page.
"""

from __future__ import annotations

from .engine import Severity, Threat
from .model import Classification, ElementKind, Model

SHAPES = {
    ElementKind.PROCESS: ("([", "])"),
    ElementKind.STORE: ("[(", ")]"),
    ElementKind.EXTERNAL: ("[", "]"),
}

SEVERITY_FILL = {
    Severity.CRITICAL: ("#ffe0e0", "#cf222e"),
    Severity.HIGH: ("#fff0e0", "#bc4c00"),
    Severity.MEDIUM: ("#fff8dc", "#9a6700"),
    Severity.LOW: ("#e9f7ef", "#1a7f37"),
}


def _safe(text: str) -> str:
    """Mermaid labels break on quotes and brackets."""
    return text.replace('"', "'").replace("[", "(").replace("]", ")")


def _node(element_id: str, label: str, kind: ElementKind) -> str:
    open_shape, close_shape = SHAPES.get(kind, ("[", "]"))
    return f'    {element_id}{open_shape}"{_safe(label)}"{close_shape}'


def render(
    model: Model,
    threats: list[Threat] | None = None,
    *,
    show_risk: bool = False,
    direction: str = "LR",
) -> str:
    """Render the model as a Mermaid flowchart."""
    lines = [f"flowchart {direction}"]

    worst: dict[str, Severity] = {}
    if threats:
        for threat in threats:
            if threat.accepted:
                continue
            current = worst.get(threat.subject_id)
            if current is None or threat.severity.rank > current.rank:
                worst[threat.subject_id] = threat.severity

    # Grouped by trust boundary, because the boundary is the thing the reader
    # is meant to notice.
    placed: set[str] = set()
    for boundary in model.boundaries:
        members = [e for e in model.elements if e.boundary == boundary.id]
        if not members:
            continue
        lines.append(f'    subgraph {boundary.id}["{_safe(boundary.name)}"]')
        for element in members:
            lines.append("    " + _node(element.id, element.name, element.kind).strip())
            placed.add(element.id)
        lines.append("    end")

    outside = [e for e in model.elements if e.id not in placed]
    for element in outside:
        lines.append(_node(element.id, element.name, element.kind))

    for flow in model.flows:
        label = flow.name
        if flow.protocol:
            label += f" ({flow.protocol})"
        marks = []
        if not flow.authenticated:
            marks.append("unauth")
        if not flow.encrypted and flow.max_classification.impact_weight >= 3:
            marks.append("cleartext")
        if marks:
            label += " ⚠ " + ", ".join(marks)
        # Dashed edges are the ones without authentication - the eye finds them
        # before it reads any label.
        arrow = "-.->" if not flow.authenticated else "-->"
        lines.append(f'    {flow.source} {arrow}|"{_safe(label)}"| {flow.target}')

    if show_risk and worst:
        lines.append("")
        for element_id, severity in sorted(worst.items()):
            if element_id not in {e.id for e in model.elements}:
                continue
            fill, stroke = SEVERITY_FILL[severity]
            lines.append(
                f"    style {element_id} fill:{fill},stroke:{stroke},stroke-width:2px"
            )

    return "\n".join(lines)


def legend() -> str:
    return (
        "```\n"
        "([ process ])   [( data store )]   [ external entity ]\n"
        "-->  authenticated flow      -.->  unauthenticated flow\n"
        "⚠ unauth      no authentication declared\n"
        "⚠ cleartext   sensitive data with no transport encryption\n"
        "```"
    )


def data_summary(model: Model) -> str:
    """A short table of what data lives where. Often the whole review."""
    rows = ["| Element | Kind | Zone | Data |", "| --- | --- | --- | --- |"]
    for element in model.elements:
        boundary = model.boundary(element.boundary)
        data = ", ".join(sorted({c.value for c in element.data})) or "—"
        marker = (
            " ⚠"
            if any(c in (Classification.PII, Classification.SECRET) for c in element.data)
            else ""
        )
        rows.append(
            f"| `{element.id}` | {element.kind.label} | "
            f"{boundary.name if boundary else '—'} | {data}{marker} |"
        )
    return "\n".join(rows)
