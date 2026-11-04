from __future__ import annotations

import math
from dataclasses import replace
from datetime import datetime, timezone

import pytest

from cvebeacon.errors import ConfigurationError
from cvebeacon.watch.records import CVSSEntry, WatchView, epss_band
from cvebeacon.watch.rules import (
    AlertSnapshot,
    EPSS_BAND_LABELS,
    SEVERITY_BANDS,
    describe_condition,
    evaluate,
    evaluate_condition,
    parse_condition,
    parse_rules,
    rule_epss_thresholds,
    snapshot_for,
)

NOW = datetime(2026, 11, 3, 7, 0, tzinfo=timezone.utc)


def view(identifier: str = "CVE-2026-0001", **overrides) -> WatchView:
    values = {
        "cve_id": identifier,
        "status": "published",
        "description": "Example vulnerability in Apache Log4j2",
        "source_identifier": "security@example.com",
        "cvss": (CVSSEntry("cna", "security@example.com", "3.1", 9.8),),
        "cwes": ("CWE-79",),
        "vendors": ("Apache Software Foundation",),
        "products": ("Apache Log4j2",),
        "ssvc_exploitation": None,
    }
    values.update(overrides)
    return WatchView(**values)


def rule(raw: dict):
    values = {"name": "test-rule", "channels": ["soc"], "condition": {"cvss_min": 9}}
    values.update(raw)
    return parse_rules([values])[0]


def assert_match(condition: dict, record: WatchView | None = None) -> tuple:
    parsed = parse_condition(condition)
    current = record or view()
    matched, reasons = evaluate_condition(current, parsed, rule({"condition": condition}))
    assert matched
    return reasons


def test_every_leaf():
    reasons = assert_match({"cvss_min": 9.0})
    assert reasons == ("cvss 9.8 (cna)",)
    assert_match({"cvss_max": 10.0})
    with pytest.raises(AssertionError):
        assert_match({"cvss_min": 10.0})
    with pytest.raises(AssertionError):
        assert_match({"cvss_max": 9.0})
    assert_match({"epss_min": 0.5}, view(epss=0.5))
    with pytest.raises(AssertionError):
        assert_match({"epss_min": 0.5})
    assert_match({"kev": "cisa"}, view(cisa_kev_added="2026-11-01"))
    assert_match({"kev": "eu"}, view(eu_kev_added="2026-11-01"))
    assert_match({"kev": "any"}, view(eu_kev_added="2026-11-01"))
    with pytest.raises(AssertionError):
        assert_match({"kev": "any"})
    assert_match({"exploitation": "poc"}, view(ssvc_exploitation="poc"))
    assert_match({"exploitation": "poc"}, view(ssvc_exploitation="active"))
    assert_match({"exploitation": "active"}, view(ssvc_exploitation="active"))
    with pytest.raises(AssertionError):
        assert_match({"exploitation": "active"}, view(ssvc_exploitation="poc"))
    assert_match({"vendor": ["apache software foundation"]})
    assert_match({"product": ["apache log4j2"]})
    assert_match({"keyword": ["LOG4J"]})
    assert_match({"cwe": ["cwe-79"]})
    assert_match({"cna": ["SECURITY@EXAMPLE.COM"]})
    assert_match({"status": "published"})
    with pytest.raises(AssertionError):
        assert_match({"status": "rejected"})
    with pytest.raises(AssertionError):
        assert_match({"keyword": ["missing"]})


def test_all_any_not_and_several_leaves_in_one_table():
    assert_match({"all": [{"cvss_min": 9}, {"epss_min": 0.5}]}, view(epss=0.7))
    with pytest.raises(AssertionError):
        assert_match({"all": [{"cvss_min": 9}, {"epss_min": 0.5}]}, view(epss=0.2))
    assert_match({"any": [{"cvss_min": 9}, {"epss_min": 0.5}]}, view(epss=0.7))
    assert_match({"any": [{"cvss_min": 9}, {"epss_min": 0.5}]})
    with pytest.raises(AssertionError):
        assert_match(
            {"any": [{"cvss_min": 10}, {"epss_min": 0.9}]}, view(epss=0.2)
        )
    reasons = assert_match(
        {"all": [{"cvss_min": 9}, {"not": {"vendor": ["examplecorp"]}}]}
    )
    assert any(reason.startswith("not ") for reason in reasons)
    with pytest.raises(AssertionError):
        assert_match(
            {"all": [{"cvss_min": 9}, {"not": {"vendor": ["apache software foundation"]}}]}
        )
    assert_match({"cvss_min": 9, "epss_min": 0.5}, view(epss=0.7))
    with pytest.raises(AssertionError):
        assert_match({"cvss_min": 9, "epss_min": 0.5}, view(epss=0.2))


@pytest.mark.parametrize(
    "condition",
    [
        {"all": [{"cvss_min": 9}, {"epss_min": 0.5}]},
        {"any": [{"cvss_min": 9}, {"epss_min": 0.5}]},
        {"cvss_min": 9},
        {"epss_min": 0.5},
        {"kev": "any"},
        {"all": [{"kev": "any"}, {"any": [{"cvss_min": 8}, {"epss_min": 0.5}]}]},
        {"all": [{"vendor": ["microsoft"]}, {"cvss_min": 8}]},
        {"all": [{"cvss_min": 9}, {"not": {"vendor": ["examplecorp"]}}]},
    ],
)
def test_owner_combination_examples_parse_and_evaluate(condition):
    parsed = parse_condition(condition)
    current = view(
        cvss=(CVSSEntry("nvd", "nvd@nist.gov", "3.1", 9.1),),
        vendors=("Microsoft",),
        products=("Windows",),
        cisa_kev_added="2026-11-01",
        epss=0.7,
    )
    matched, _ = evaluate_condition(current, parsed, rule({"condition": condition}))
    assert matched


@pytest.mark.parametrize(
    "condition,match",
    [
        ({"all": []}, "must not be empty"),
        ({"any": []}, "must not be empty"),
        ({}, "must not be empty"),
        ({"all": [{"cvss_min": 9}], "epss_min": 0.5}, "cannot mix"),
        ({"all": [{"cvss_min": 9}], "any": [{"cvss_min": 8}]}, "exactly one"),
        ({"unknown": 1}, "unknown key"),
        ({"cvss_min": True}, "must be a number"),
        ({"cvss_min": math.inf}, "must be a number"),
        ({"cvss_min": math.nan}, "must be a number"),
        ({"cvss_min": 10.1}, "must be a number"),
        ({"epss_min": 1.1}, "must be a number"),
        ({"kev": "all"}, "must be one of"),
        ({"exploitation": "none"}, "must be one of"),
        ({"status": "withdrawn"}, "must be one of"),
        ({"vendor": "apache"}, "must be a list"),
        ({"vendor": []}, "at least one"),
        ({"vendor": [1]}, "must be a string"),
        ({"vendor": ["x"] * 101}, "at most 100"),
        ({"vendor": ["x" * 201]}, "at most 200"),
    ],
)
def test_condition_validation_errors(condition, match):
    with pytest.raises(ConfigurationError, match=match):
        parse_condition(condition, path="watch rule 'x' condition")


def test_condition_depth_and_leaf_limits():
    condition = {"cvss_min": 9}
    for _ in range(4):
        condition = {"all": [condition]}
    parse_condition(condition)
    too_deep = {"all": [condition]}
    with pytest.raises(ConfigurationError, match="nesting depth"):
        parse_condition(too_deep)
    with pytest.raises(ConfigurationError, match="32 leaves"):
        parse_condition({"all": [{"cvss_min": 1} for _ in range(33)]})


def test_rule_validation_errors_and_error_paths():
    with pytest.raises(ConfigurationError, match="duplicate watch rule name"):
        parse_rules(
            [
                {"name": "a", "condition": {"cvss_min": 1}, "channels": ["x"]},
                {"name": "A", "condition": {"cvss_min": 1}, "channels": ["y"]},
            ]
        )
    with pytest.raises(ConfigurationError, match="name"):
        parse_rules([{"name": "bad/name", "condition": {"cvss_min": 1}, "channels": ["x"]}])
    with pytest.raises(ConfigurationError, match="name"):
        parse_rules([{"condition": {"cvss_min": 1}, "channels": ["x"]}])
    with pytest.raises(ConfigurationError, match="channels"):
        parse_rules([{"name": "a", "condition": {"cvss_min": 1}}])
    with pytest.raises(ConfigurationError, match="channels"):
        parse_rules([{"name": "a", "condition": {"cvss_min": 1}, "channels": []}])
    with pytest.raises(ConfigurationError, match="events"):
        parse_rules(
            [
                {
                    "name": "a",
                    "condition": {"cvss_min": 1},
                    "channels": ["x"],
                    "events": ["exploded"],
                }
            ]
        )
    with pytest.raises(ConfigurationError, match="cvss_providers"):
        parse_rules(
            [
                {
                    "name": "a",
                    "condition": {"cvss_min": 1},
                    "channels": ["x"],
                    "cvss_providers": ["made-up"],
                }
            ]
        )
    with pytest.raises(ConfigurationError, match="unknown key"):
        parse_rules(
            [
                {
                    "name": "a",
                    "condition": {"cvss_min": 1},
                    "channels": ["x"],
                    "magic": True,
                }
            ]
        )
    with pytest.raises(ConfigurationError, match="watch rule 'a' condition"):
        parse_rules(
            [
                {
                    "name": "a",
                    "condition": {"all": [{"cvss_min": 11}]},
                    "channels": ["x"],
                }
            ]
        )


def test_defaults_and_enabled_flag():
    parsed = rule({"condition": {"cvss_min": 1}, "enabled": False})
    assert parsed.enabled is False
    assert parsed.events == (
        "match",
        "kev_added",
        "exploitation_active",
        "severity_increase",
        "epss_increase",
        "nvd_score_added",
        "rejected",
    )
    assert parsed.cvss_providers == ("nvd", "cna", "cisa-adp", "euvd", "other")
    assert parsed.channels == ("soc",)


def test_band_computations():
    assert snapshot_for(view(cvss=()), rule({})).severity_band == "none"
    for score, band in ((0.0, "none"), (0.1, "low"), (3.9, "low"), (4.0, "medium"), (7.0, "high"), (9.0, "critical")):
        current = view(cvss=(CVSSEntry("nvd", "nvd@nist.gov", "3.1", score),))
        assert snapshot_for(current, rule({})).severity_band == band
    for value, band in ((None, "none"), (0.0, "<0.1"), (0.1, "<0.5"), (0.5, "<0.9"), (0.9, ">=0.9")):
        assert snapshot_for(view(epss=value), rule({})).epss_band == band
    assert [epss_band(value) for value in (None, 0.0, 0.1, 0.5, 0.9)] == [-1, 0, 1, 2, 3]
    assert SEVERITY_BANDS == ("none", "low", "medium", "high", "critical")
    assert EPSS_BAND_LABELS == ("none", "<0.1", "<0.5", "<0.9", ">=0.9")


def test_match_reasons_and_state():
    current = view(epss=0.62)
    state, events = evaluate(
        current,
        None,
        rule({"condition": {"any": [{"cvss_min": 9}, {"epss_min": 0.5}]}}),
        now=NOW,
    )
    assert state is not None
    assert state.first_matched_at == NOW.isoformat()
    assert state.snapshot.severity_band == "critical"
    assert len(events) == 1 and events[0].kind == "match"
    assert "cvss 9.8 (cna)" in events[0].reasons
    assert "epss 0.62" in events[0].reasons


def test_no_previous_state_and_no_match_stores_nothing():
    state, events = evaluate(view(cvss=()), None, rule({}), now=NOW)
    assert state is None and events == ()


@pytest.mark.parametrize(
    "changed,kind,expected",
    [
        ({"cisa_kev_added": "2026-11-03"}, "kev_added", "kev cisa false \u2192 true"),
        ({"eu_kev_added": "2026-11-03"}, "kev_added", "kev eu false \u2192 true"),
        ({"ssvc_exploitation": "active"}, "exploitation_active", "exploitation none \u2192 active"),
        (
            {"cvss": (CVSSEntry("cna", "security@example.com", "3.1", 9.8),)},
            "severity_increase",
            "severity high \u2192 critical",
        ),
        ({"epss": 0.6}, "epss_increase", "epss <0.5 \u2192 <0.9"),
        (
            {
                "cvss": (
                    CVSSEntry("cna", "security@example.com", "3.1", 8.0),
                    CVSSEntry("nvd", "nvd@nist.gov", "3.1", 8.0),
                )
            },
            "nvd_score_added",
            "nvd score absent \u2192 present",
        ),
        ({"status": "rejected"}, "rejected", "status published \u2192 rejected"),
    ],
)
def test_each_escalation_kind(changed, kind, expected):
    baseline = view(
        cvss=(CVSSEntry("cna", "security@example.com", "3.1", 8.0),),
        epss=0.2,
    )
    configured = rule({"condition": {"cvss_min": 1}})
    state, events = evaluate(baseline, None, configured, now=NOW)
    assert events[0].kind == "match"
    updated = replace(baseline, **changed)
    state, events = evaluate(updated, state, configured, now=NOW)
    assert [event.kind for event in events] == [kind]
    assert events[0].reasons == (expected,)
    assert state is not None


def test_escalations_require_a_prior_match_and_only_configured_kinds():
    configured = rule({"condition": {"cvss_min": 10}})
    state, events = evaluate(view(), None, configured, now=NOW)
    assert state is None and events == ()
    matched = rule({"condition": {"cvss_min": 9}})
    state, events = evaluate(view(), None, matched, now=NOW)
    assert state is not None and events[0].kind == "match"

    only_match = rule({"condition": {"cvss_min": 9}, "events": ["match"]})
    state, events = evaluate(view(), None, only_match, now=NOW)
    assert state is not None and [event.kind for event in events] == ["match"]
    state, events = evaluate(
        view(cisa_kev_added="2026-11-03"), state, only_match, now=NOW
    )
    assert state is not None and events == ()


def test_first_epss_score_below_the_lowest_band_does_not_escalate():
    configured = rule({"condition": {"cvss_min": 9}})
    state, events = evaluate(view(epss=None), None, configured, now=NOW)
    assert state is not None and events[0].kind == "match"
    state, events = evaluate(view(epss=0.001), state, configured, now=NOW)
    assert state is not None and events == ()
    assert state.snapshot.epss_band == "<0.1"


def test_first_epss_score_in_the_first_alert_band_escalates():
    configured = rule({"condition": {"cvss_min": 9}})
    state, _ = evaluate(view(epss=None), None, configured, now=NOW)
    state, events = evaluate(view(epss=0.2), state, configured, now=NOW)
    assert state is not None
    assert [event.kind for event in events] == ["epss_increase"]
    assert events[0].reasons == ("epss none \u2192 <0.5",)
    assert state.snapshot.epss_band == "<0.5"


def test_epss_crossing_from_the_lowest_band_escalates():
    configured = rule({"condition": {"cvss_min": 9}})
    state, _ = evaluate(view(epss=0.001), None, configured, now=NOW)
    state, events = evaluate(view(epss=0.2), state, configured, now=NOW)
    assert state is not None
    assert [event.kind for event in events] == ["epss_increase"]
    assert events[0].reasons == ("epss <0.1 \u2192 <0.5",)
    assert state.snapshot.epss_band == "<0.5"


def test_decreases_and_band_steps_are_silent():
    configured = rule({"condition": {"cvss_min": 9}})
    state, _ = evaluate(
        view(
            cvss=(CVSSEntry("nvd", "nvd@nist.gov", "3.1", 9.8),),
            epss=0.95,
            cisa_kev_added="2026-11-01",
            ssvc_exploitation="active",
        ),
        None,
        configured,
        now=NOW,
    )
    lowered = view(
        cvss=(CVSSEntry("nvd", "nvd@nist.gov", "3.1", 4.0),),
        epss=0.2,
    )
    state, events = evaluate(lowered, state, configured, now=NOW)
    assert state is not None and events == ()
    assert state.snapshot.severity_band == "medium"
    assert state.snapshot.epss_band == "<0.5"
    assert state.snapshot.cisa_kev is False
    assert state.snapshot.exploitation == "none"


def test_cvss_provider_selection():
    nvd_only = rule({"condition": {"cvss_min": 9}, "cvss_providers": ["nvd"]})
    state, events = evaluate(view(), None, nvd_only, now=NOW)
    assert state is None and events == ()
    state, events = evaluate(
        view(cvss=(CVSSEntry("nvd", "nvd@nist.gov", "3.1", 9.1),)),
        None,
        nvd_only,
        now=NOW,
    )
    assert state is not None
    all_providers = rule({"condition": {"cvss_min": 9}})
    state, events = evaluate(view(), None, all_providers, now=NOW)
    assert state is not None


def test_rejected_match_requires_an_explicit_rejected_leaf():
    rejected = view(status="rejected")
    state, events = evaluate(rejected, None, rule({"condition": {"cvss_min": 0}}), now=NOW)
    assert state is None and events == ()
    explicit = rule({"condition": {"any": [{"status": "rejected"}, {"cvss_min": 9}]}})
    state, events = evaluate(rejected, None, explicit, now=NOW)
    assert state is not None and events[0].kind == "match"
    assert "status rejected" in events[0].reasons


def test_nvd_score_added_uses_any_provider_score_even_when_not_selected():
    configured = rule({"condition": {"cvss_min": 9}, "cvss_providers": ["cna"]})
    state, _ = evaluate(view(), None, configured, now=NOW)
    state, events = evaluate(
        view(
            cvss=(
                CVSSEntry("cna", "security@example.com", "3.1", 9.8),
                CVSSEntry("nvd", "nvd@nist.gov", "3.1", 9.5),
            )
        ),
        state,
        configured,
        now=NOW,
    )
    assert [event.kind for event in events] == ["nvd_score_added"]
    assert state is not None and state.snapshot.nvd_score is True


def test_describe_condition_and_epss_thresholds():
    configured = rule(
        {
            "condition": {"any": [{"cvss_min": 9.0}, {"epss_min": 0.5}]},
            "name": "critical-or-likely",
        }
    )
    assert describe_condition(configured.condition) == "(cvss \u2265 9.0 OR epss \u2265 0.5)"
    disabled = rule(
        {"condition": {"epss_min": 0.3}, "enabled": False, "name": "off"}
    )
    assert rule_epss_thresholds((configured, disabled)) == (0.5,)


def test_snapshot_json_round_trip():
    snapshot = snapshot_for(view(epss=0.6, cisa_kev_added="2026-11-01"), rule({}))
    assert AlertSnapshot.from_dict(snapshot.as_dict()) == snapshot
    with pytest.raises(ValueError):
        AlertSnapshot.from_dict({"cisa_kev": "yes"})
