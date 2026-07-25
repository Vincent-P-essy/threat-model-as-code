"""Model parsing, conditional enumeration, scoring, stories and drift."""

from __future__ import annotations

from pathlib import Path

import pytest

from tmac.diagram import render
from tmac.drift import check as check_drift
from tmac.drift import scan
from tmac.engine import Severity, band, enumerate_threats, summarise
from tmac.model import Classification, ElementKind, ModelError, load, parse
from tmac.report import render_markdown
from tmac.stories import generate
from tmac.stride import CONTROLS, RULES, Stride, applicable, unknown_controls

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "payments-api.yaml"
APP = Path(__file__).resolve().parent.parent / "examples" / "app"

MINIMAL = {
    "name": "t",
    "boundaries": [{"id": "in"}, {"id": "out"}],
    "elements": [
        {"id": "client", "kind": "external", "boundary": "out"},
        {"id": "api", "kind": "process", "boundary": "in", "data": ["pii"]},
        {"id": "db", "kind": "store", "boundary": "in", "data": ["pii"]},
    ],
    "flows": [
        {"id": "f1", "source": "client", "target": "api", "data": ["pii"]},
        {"id": "f2", "source": "api", "target": "db", "data": ["pii"], "authenticated": True},
    ],
}


class TestModel:
    def test_example_loads(self):
        model = load(EXAMPLE)
        assert model.name.startswith("SEPA")
        assert len(model.elements) == 8
        assert len(model.flows) == 7

    def test_missing_file(self, tmp_path):
        with pytest.raises(ModelError, match="not found"):
            load(tmp_path / "nope.yaml")

    def test_missing_name(self):
        with pytest.raises(ModelError, match="'name'"):
            parse({"elements": []})

    def test_unknown_kind_names_the_element(self):
        with pytest.raises(ModelError, match="element 'x'.*unknown kind"):
            parse({"name": "t", "elements": [{"id": "x", "kind": "wizard"}]})

    def test_unknown_classification(self):
        with pytest.raises(ModelError, match="unknown data classification"):
            parse({"name": "t", "elements": [{"id": "x", "data": ["top-secret"]}]})

    def test_undeclared_boundary_lists_the_valid_ones(self):
        with pytest.raises(ModelError, match="undeclared boundary.*Declared"):
            parse({"name": "t", "boundaries": [{"id": "a"}],
                   "elements": [{"id": "x", "boundary": "b"}]})

    def test_flow_to_nowhere(self):
        with pytest.raises(ModelError, match="target 'ghost' is not a declared element"):
            parse({"name": "t", "elements": [{"id": "a"}],
                   "flows": [{"id": "f", "source": "a", "target": "ghost"}]})

    def test_duplicate_element_ids(self):
        with pytest.raises(ModelError, match="duplicate element id"):
            parse({"name": "t", "elements": [{"id": "a"}, {"id": "a"}]})

    def test_accepting_a_risk_requires_a_reason(self):
        # Accepting risk is a legitimate decision. Doing it silently is how it
        # stops being one, so the loader refuses.
        with pytest.raises(ModelError, match="no reason"):
            parse({"name": "t", "elements": [{"id": "a", "accepted": {"F-SPOOF-01": ""}}]})

    def test_boundary_crossing(self):
        model = parse(MINIMAL)
        assert model.crosses_boundary(model.flows[0])
        assert not model.crosses_boundary(model.flows[1])

    def test_element_without_a_boundary_counts_as_crossing(self):
        # An unplaced element is either outside every zone or an oversight.
        # Both deserve the threats.
        model = parse({"name": "t",
                       "elements": [{"id": "a"}, {"id": "b", "boundary": None}],
                       "flows": [{"id": "f", "source": "a", "target": "b"}]})
        assert model.crosses_boundary(model.flows[0])

    def test_max_classification(self):
        model = parse(MINIMAL)
        assert model.element("api").max_classification is Classification.PII

    def test_stats(self):
        stats = parse(MINIMAL).stats()
        assert stats["process"] == 1 and stats["store"] == 1 and stats["external"] == 1
        assert stats["crossing_flows"] == 1


class TestEnumeration:
    def test_rules_are_conditional_not_blanket(self):
        # The failure mode this guards: emitting all six STRIDE categories for
        # every element, which produces findings nobody reads.
        model = parse(MINIMAL)
        api = model.element("api")
        fired = applicable(api, model)
        assert fired
        assert len(fired) < len([r for r in RULES if ElementKind.PROCESS in r.applies_to]) + 1

    def test_authenticated_flow_does_not_raise_the_spoofing_rule(self):
        model = parse(MINIMAL)
        unauth, auth = model.flows[0], model.flows[1]
        assert any(r.id == "F-SPOOF-01" for r in applicable(unauth, model))
        assert not any(r.id == "F-SPOOF-01" for r in applicable(auth, model))

    def test_declared_control_lowers_residual_but_not_inherent(self):
        with_control = dict(MINIMAL)
        with_control["flows"] = [
            {**MINIMAL["flows"][0], "controls": ["mtls", "oauth2"]},
            MINIMAL["flows"][1],
        ]
        plain = {t.id: t for t in enumerate_threats(parse(MINIMAL))}
        armed = {t.id: t for t in enumerate_threats(parse(with_control))}
        target = "F-SPOOF-01@f1"
        assert armed[target].inherent_risk == plain[target].inherent_risk
        assert armed[target].residual_risk < plain[target].residual_risk

    def test_control_credit_is_capped(self):
        # Listing every control in the library must not zero the score.
        loaded = dict(MINIMAL)
        loaded["flows"] = [
            {**MINIMAL["flows"][0], "controls": list(CONTROLS)},
            MINIMAL["flows"][1],
        ]
        threats = {t.id: t for t in enumerate_threats(parse(loaded))}
        assert threats["F-SPOOF-01@f1"].residual_risk >= 1

    def test_impact_follows_data_classification(self):
        public = parse({**MINIMAL, "elements": [
            {"id": "client", "kind": "external", "boundary": "out"},
            {"id": "api", "kind": "process", "boundary": "in", "data": ["public"]},
            {"id": "db", "kind": "store", "boundary": "in", "data": ["public"]},
        ], "flows": [{"id": "f1", "source": "client", "target": "api", "data": ["public"]}]})
        secret = parse({**MINIMAL, "elements": [
            {"id": "client", "kind": "external", "boundary": "out"},
            {"id": "api", "kind": "process", "boundary": "in", "data": ["secret"]},
            {"id": "db", "kind": "store", "boundary": "in", "data": ["secret"]},
        ], "flows": [{"id": "f1", "source": "client", "target": "api", "data": ["secret"]}]})
        def spoof_impact(model):
            # One rule, one subject: other rules carry their own base impact and
            # would mask the effect being tested.
            return next(
                t.impact for t in enumerate_threats(model) if t.id == "F-SPOOF-01@f1"
            )

        assert spoof_impact(secret) > spoof_impact(public)

    def test_accepted_threats_leave_the_open_count(self):
        model = load(EXAMPLE)
        threats = enumerate_threats(model)
        accepted = [t for t in threats if t.accepted]
        assert accepted, "the example should demonstrate an accepted risk"
        assert all(not t.open for t in accepted)
        assert all(t.accepted_reason for t in accepted)

    def test_every_threat_explains_its_score(self):
        for threat in enumerate_threats(load(EXAMPLE)):
            assert threat.rule.description
            assert threat.missing_controls or threat.applied_controls

    def test_ranked_by_residual_risk(self):
        threats = enumerate_threats(load(EXAMPLE))
        assert [t.residual_risk for t in threats] == sorted(
            (t.residual_risk for t in threats), reverse=True
        )

    def test_severity_bands_discriminate(self):
        # A report where two thirds of findings are critical ranks nothing.
        summary = summarise(enumerate_threats(load(EXAMPLE)))
        assert summary.by_severity[Severity.CRITICAL] < summary.total * 0.5
        assert summary.by_severity[Severity.HIGH] > 0

    @pytest.mark.parametrize(
        "score,expected",
        [(25, Severity.CRITICAL), (20, Severity.CRITICAL), (16, Severity.HIGH),
         (12, Severity.HIGH), (9, Severity.MEDIUM), (6, Severity.MEDIUM),
         (4, Severity.LOW), (1, Severity.LOW)],
    )
    def test_bands(self, score, expected):
        assert band(score) is expected

    def test_summary_reduction(self):
        summary = summarise(enumerate_threats(load(EXAMPLE)))
        assert 0 <= summary.risk_reduction < 1
        assert summary.residual_total <= summary.inherent_total

    def test_unknown_control_is_reported(self):
        model = parse({**MINIMAL, "elements": [
            {"id": "client", "kind": "external", "boundary": "out"},
            {"id": "api", "kind": "process", "boundary": "in", "controls": ["magic_shield"]},
            {"id": "db", "kind": "store", "boundary": "in"},
        ]})
        # A typo'd control silently means "no mitigation" and quietly inflates
        # the residual score, so it must be surfaced.
        assert unknown_controls(model) == {"api": ["magic_shield"]}

    def test_rule_ids_are_unique(self):
        ids = [r.id for r in RULES]
        assert len(ids) == len(set(ids))

    def test_every_rule_names_a_real_control(self):
        for rule in RULES:
            unknown = [c for c in rule.mitigations if c not in CONTROLS]
            assert not unknown, f"{rule.id} references unknown control(s) {unknown}"

    def test_every_control_addresses_something(self):
        for control in CONTROLS.values():
            assert control.addresses
            assert 0 < control.likelihood_reduction <= 1

    def test_every_stride_category_is_covered_by_a_rule(self):
        covered = {rule.category for rule in RULES}
        assert covered == set(Stride)


class TestDiagram:
    def test_renders_mermaid(self):
        body = render(load(EXAMPLE))
        assert body.startswith("flowchart LR")
        assert "subgraph core" in body
        assert "-.->" in body  # at least one unauthenticated flow

    def test_labels_are_escaped(self):
        model = parse({"name": "t", "elements": [{"id": "a", "name": 'has "quotes" [and] brackets'}]})
        assert '"' not in render(model).split("a[")[-1].split("\n")[0].strip('"')

    def test_risk_shading_is_opt_in(self):
        model = load(EXAMPLE)
        threats = enumerate_threats(model)
        assert "style" not in render(model, threats)
        assert "style" in render(model, threats, show_risk=True)


class TestStories:
    def test_generated_from_open_threats(self):
        stories = generate(enumerate_threats(load(EXAMPLE)))
        assert stories
        assert all(s.criteria for s in stories)
        assert all(s.points > 0 for s in stories)

    def test_grouped_by_control_and_subject(self):
        # Eleven threats answered by one control on one component are one piece
        # of work, not eleven.
        stories = generate(enumerate_threats(load(EXAMPLE)))
        keys = [(s.control.id, s.subject_id) for s in stories]
        assert len(keys) == len(set(keys))

    def test_low_severity_does_not_generate_work(self):
        stories = generate(enumerate_threats(load(EXAMPLE)))
        assert all(s.severity is not Severity.LOW for s in stories)

    def test_criteria_are_checkable_not_aspirational(self):
        stories = generate(enumerate_threats(load(EXAMPLE)))
        vague = {"secure", "properly", "as appropriate", "best practice"}
        for story in stories:
            for criterion in story.criteria:
                assert not any(word in criterion.lower() for word in vague), criterion

    def test_rendered_story_carries_the_threats_it_closes(self):
        story = generate(enumerate_threats(load(EXAMPLE)))[0]
        assert story.threats[0].rule.id in story.render()


class TestDrift:
    def test_scan_finds_routes_and_dependencies(self):
        observations, files = scan(APP)
        assert files == 1
        routes = [o for o in observations if o.kind == "route"]
        assert {"/v1/payments", "/ops/limits/override"} <= {o.value for o in routes}

    def test_decorators_are_not_double_counted(self):
        # Flask and FastAPI decorators are written identically; both patterns
        # match the same line.
        observations, _ = scan(APP)
        routes = [o for o in observations if o.kind == "route"]
        assert len(routes) == len({(o.file, o.line) for o in routes})

    def test_undeclared_endpoint_is_the_finding(self):
        report = check_drift(load(EXAMPLE), APP)
        assert not report.clean
        finding = next(f for f in report.findings if f.kind == "undeclared_endpoint")
        assert "/ops/limits/override" in finding.detail
        assert finding.evidence.endswith(":37")

    def test_declared_endpoints_do_not_drift(self):
        report = check_drift(load(EXAMPLE), APP)
        assert not any("/v1/payments" in f.detail for f in report.findings)

    def test_a_scanner_does_not_report_its_own_regexes(self):
        # Without the re.compile guard, every scanner finds "mysql://" in its
        # own pattern table and reports a dependency that does not exist.
        report = check_drift(load(EXAMPLE), Path(__file__).resolve().parent.parent / "src")
        assert not any(f.kind == "undeclared_dependency" for f in report.findings)

    def test_credentials_are_redacted_from_evidence(self):
        # Drift reports get pasted into pull requests.
        from tmac.drift import _redact

        assert _redact("postgresql://user:hunter2@host/db") == "postgresql://***@host/db"

    def test_report_serialises(self):
        import json

        json.dumps(check_drift(load(EXAMPLE), APP).to_dict())


class TestReport:
    def test_markdown_has_the_sections_that_matter(self):
        model = load(EXAMPLE)
        threats = enumerate_threats(model)
        text = render_markdown(model, threats, summarise(threats))
        assert "```mermaid" in text
        assert "Accepted risks" in text
        assert "Why this score" in text
        assert "Controls that would close it" in text
