"""Command line interface.

``analyse`` takes ``--fail-over`` so it can gate a pipeline, and ``drift`` exits
non-zero on a stale model. Both default to off: a check that starts failing
builds the day it is installed gets removed the same week.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.text import Text

from . import __version__
from .diagram import legend, render
from .drift import check as check_drift
from .engine import Severity, enumerate_threats, summarise
from .model import ModelError, load
from .report import render_markdown, render_terminal
from .stories import generate, render_backlog
from .stride import CONTROLS, RULES, unknown_controls


def _load(args: argparse.Namespace, console: Console):
    model = load(args.model)
    unknown = unknown_controls(model)
    if unknown:
        # A typo'd control id silently means "no mitigation", which inflates the
        # residual score with no error anywhere. Never let it pass quietly.
        for subject, ids in unknown.items():
            console.print(
                f"[yellow]warning[/] `{subject}` declares unknown control(s): "
                f"{', '.join(ids)} — they count for nothing in the score"
            )
    return model


def cmd_analyse(args: argparse.Namespace, console: Console) -> int:
    model = _load(args, console)
    threats = enumerate_threats(model)
    summary = summarise(threats)

    if args.json:
        print(
            json.dumps(
                {
                    "model": {"name": model.name, "version": model.version, **model.stats()},
                    "summary": summary.to_dict(),
                    "threats": [t.to_dict() for t in threats],
                },
                indent=2,
            )
        )
    else:
        render_terminal(model, threats, summary, console, limit=args.limit)

    if args.markdown:
        Path(args.markdown).write_text(
            render_markdown(model, threats, summary), encoding="utf-8"
        )
        console.print(f"[dim]wrote {args.markdown}[/]")

    if args.fail_over is not None:
        breaching = [
            t for t in threats
            if not t.accepted and t.severity.rank >= Severity(args.fail_over).rank
        ]
        if breaching:
            console.print(
                f"\n[bold red]FAIL[/] {len(breaching)} unaccepted threat(s) at "
                f"{args.fail_over} or above"
            )
            return 1
    return 0


def cmd_diagram(args: argparse.Namespace, console: Console) -> int:
    model = _load(args, console)
    threats = enumerate_threats(model) if args.risk else None
    body = render(model, threats, show_risk=args.risk, direction=args.direction)
    output = f"```mermaid\n{body}\n```\n\n{legend()}\n"
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        console.print(f"[dim]wrote {args.out}[/]")
    else:
        print(output)
    return 0


def cmd_stories(args: argparse.Namespace, console: Console) -> int:
    model = _load(args, console)
    stories = generate(enumerate_threats(model))
    backlog = render_backlog(stories, model.name)
    if args.out:
        Path(args.out).write_text(backlog, encoding="utf-8")
        console.print(
            f"[green]{len(stories)} stories[/], {sum(s.points for s in stories)} points "
            f"→ {args.out}"
        )
        return 0

    table = Table(
        title=f"Security backlog — {len(stories)} items, "
        f"{sum(s.points for s in stories)} points",
        title_style="bold",
        header_style="dim",
    )
    table.add_column("id", style="bold")
    table.add_column("sev")
    table.add_column("pts", justify="right")
    table.add_column("story", overflow="fold")
    table.add_column("closes", justify="right", style="dim")
    styles = {
        Severity.CRITICAL: "bright_red", Severity.HIGH: "red",
        Severity.MEDIUM: "yellow", Severity.LOW: "green",
    }
    for story in stories:
        table.add_row(
            story.id,
            Text(story.severity.value, style=styles[story.severity]),
            str(story.points),
            story.title,
            f"{len(story.threats)} threat(s)",
        )
    console.print(table)
    return 0


def cmd_drift(args: argparse.Namespace, console: Console) -> int:
    model = _load(args, console)
    report = check_drift(model, args.path)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return 0 if report.clean else 1

    routes = [o for o in report.observations if o.kind == "route"]
    deps = [o for o in report.observations if o.kind == "dependency"]
    console.print(
        f"scanned [bold]{report.files_scanned}[/] source file(s): "
        f"{len(routes)} route(s), {len(deps)} outbound dependency reference(s)"
    )

    if report.clean:
        console.print("[bold green]no drift detected[/] — the model matches what the code does")
        return 0

    table = Table(title="Model drift", title_style="bold", header_style="dim")
    table.add_column("sev")
    table.add_column("kind", style="bold")
    table.add_column("detail", overflow="fold")
    table.add_column("evidence", style="dim")
    colours = {"high": "bright_red", "medium": "yellow", "low": "cyan"}
    for finding in report.findings:
        table.add_row(
            Text(finding.severity, style=colours.get(finding.severity, "white")),
            finding.kind,
            finding.detail,
            finding.evidence,
        )
    console.print(table)
    return 1 if args.strict else 0


def cmd_validate(args: argparse.Namespace, console: Console) -> int:
    try:
        model = load(args.model)
    except ModelError as exc:
        console.print(f"[bold red]invalid model:[/] {exc}")
        return 1

    console.print(f"[green]OK[/]   parsed [bold]{model.name}[/] v{model.version}")
    stats = model.stats()
    console.print(
        f"[green]OK[/]   {stats['process']} processes, {stats['store']} stores, "
        f"{stats['external']} external entities, {stats['flow']} flows"
    )

    unknown = unknown_controls(model)
    if unknown:
        for subject, ids in unknown.items():
            console.print(f"[bold red]FAIL[/] `{subject}` declares unknown control(s): "
                          f"{', '.join(ids)}")
        console.print(f"[dim]     known controls: {', '.join(sorted(CONTROLS))}[/]")
        return 1
    console.print(f"[green]OK[/]   every declared control exists ({len(CONTROLS)} in the library)")

    orphans = [
        e.id for e in model.elements
        if not model.flows_touching(e.id) and len(model.elements) > 1
    ]
    if orphans:
        console.print(
            f"[yellow]WARN[/] element(s) with no flows: {', '.join(orphans)} — "
            "they generate almost no threats, which may not be what you meant"
        )

    unplaced = [e.id for e in model.elements if e.boundary is None]
    if unplaced:
        console.print(
            f"[yellow]WARN[/] element(s) in no trust boundary: {', '.join(unplaced)} — "
            "every flow touching them is treated as boundary-crossing"
        )

    console.print("\n[bold green]model is valid[/]")
    return 0


def cmd_rules(args: argparse.Namespace, console: Console) -> int:
    table = Table(title=f"Threat rules ({len(RULES)})", title_style="bold", header_style="dim")
    table.add_column("id", style="bold")
    table.add_column("category", style="magenta")
    table.add_column("applies to", style="cyan")
    table.add_column("L", justify="center")
    table.add_column("I", justify="center")
    table.add_column("fires when / mitigations", overflow="fold")
    for rule in RULES:
        table.add_row(
            rule.id,
            rule.category.label,
            ", ".join(k.value for k in rule.applies_to),
            str(rule.base_likelihood),
            str(rule.base_impact),
            f"{rule.title}\n[dim]{', '.join(rule.mitigations)}[/]",
        )
    console.print(table)
    console.print(
        f"\n[dim]Every rule is conditional: it fires only when the model says its "
        f"preconditions hold. {len(CONTROLS)} controls in the library.[/]"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tmac", description="Threat modelling as code.")
    parser.add_argument("--version", action="version", version=f"tmac {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("analyse", help="enumerate and score threats")
    p.add_argument("model")
    p.add_argument("--json", action="store_true")
    p.add_argument("--markdown", help="write a full report to this path")
    p.add_argument("--limit", type=int, default=12)
    p.add_argument(
        "--fail-over",
        choices=[s.value for s in Severity],
        help="exit 1 if any unaccepted threat reaches this severity",
    )
    p.set_defaults(func=cmd_analyse)

    p = sub.add_parser("diagram", help="render the data-flow diagram as Mermaid")
    p.add_argument("model")
    p.add_argument("--risk", action="store_true", help="shade elements by residual severity")
    p.add_argument("--direction", default="LR", choices=["LR", "TB", "RL", "BT"])
    p.add_argument("--out")
    p.set_defaults(func=cmd_diagram)

    p = sub.add_parser("stories", help="generate the security backlog")
    p.add_argument("model")
    p.add_argument("--out")
    p.set_defaults(func=cmd_stories)

    p = sub.add_parser("drift", help="check the model against a source tree")
    p.add_argument("model")
    p.add_argument("path", help="root of the codebase")
    p.add_argument("--json", action="store_true")
    p.add_argument("--strict", action="store_true", help="exit 1 on any drift")
    p.set_defaults(func=cmd_drift)

    p = sub.add_parser("validate", help="check the model file is sound")
    p.add_argument("model")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("rules", help="list the threat rules and controls")
    p.set_defaults(func=cmd_rules)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console()
    try:
        return int(args.func(args, console))
    except ModelError as exc:
        console.print(f"[bold red]model error:[/] {exc}")
        return 2
    except (OSError, ValueError) as exc:
        console.print(f"[bold red]error:[/] {exc}")
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
