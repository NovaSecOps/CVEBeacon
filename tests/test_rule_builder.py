from __future__ import annotations

import itertools
import math

import pytest

from cvebeacon.rule_builder import (
    BUILD_FIELD_CRITERIA,
    BUILD_FIELD_JOIN,
    CRITERIA,
    CRITERIA_BY_KEY,
    EXCLUDE_HELP,
    MATCH_HELP,
    MATCH_OPTIONS,
    NO_CRITERIA_MESSAGE,
    REASONS,
    REASON_COMMA,
    REASON_MULTIPLE_KEYS,
    REASON_NESTED,
    REASON_QUALIFIED,
    REASON_REPEATED,
    REASON_UNREADABLE,
    USE_OPTIONS,
    Model,
    build_model,
    describe,
    from_model,
    keep_original_condition,
    read_condition,
    to_model,
)
from cvebeacon.watch.rules import (
    CONDITION_SCHEMA,
    MAX_DEPTH,
    MAX_LIST_ITEMS,
    MAX_STRING,
    Rule,
    condition_payload,
    parse_condition,
    rule_hash,
)

BANNED_WORDS = ("protected", "all set", "working", "healthy", "safe", "not affected")

SAMPLES = {
    "kev": "cisa",
    "exploitation": "poc",
    "cvss_min": 9.0,
    "cvss_max": 10.0,
    "epss_min": 0.5,
    "vendor": ("Example Corp",),
    "product": ("Widget",),
    "keyword": ("remote code execution",),
    "cwe": ("CWE-79",),
    "cna": ("Example",),
    "status": "rejected",
}

DOC_CONDITIONS = [
    # docs/WATCH.md "A condition is a small boolean tree" examples.
    ({"all": [{"cvss_min": 9.0}, {"epss_min": 0.5}]}, None),
    ({"any": [{"cvss_min": 9.0}, {"epss_min": 0.5}]}, None),
    ({"cvss_min": 9.0}, None),
    ({"cvss_min": {"score": 9.0, "versions": ["4.0", "3.1"]}}, REASON_QUALIFIED),
    ({"epss_min": 0.5}, None),
    ({"kev": "any"}, None),
    (
        {"all": [{"kev": "any"}, {"any": [{"cvss_min": 8}, {"epss_min": 0.5}]}]},
        REASON_NESTED,
    ),
    ({"all": [{"vendor": ["microsoft"]}, {"cvss_min": 8}]}, None),
    ({"all": [{"cvss_min": 9}, {"not": {"vendor": ["examplecorp"]}}]}, None),
    # docs/WATCH.md "Product mappings" exclusion example.
    (
        {"all": [{"vendor": ["palo_alto_networks"]},
                 {"not": {"product": ["globalprotect"]}}]},
        None,
    ),
]


def _rule(raw):
    return Rule(name="test-rule", condition=parse_condition(raw), channels=("email",))


def _condition_depth(raw) -> int:
    if not isinstance(raw, dict):
        return 0
    for key in ("all", "any"):
        if key in raw:
            return 1 + max(_condition_depth(child) for child in raw[key])
    if "not" in raw:
        return 1 + _condition_depth(raw["not"])
    return 0


def _sample_text(criterion) -> str:
    if criterion.kind == "number":
        return str(SAMPLES[criterion.key])
    if criterion.kind == "enum":
        return criterion.choices[0][0]
    if criterion.kind == "cwe":
        return "79, cwe-80"
    if criterion.key == "keyword":
        return "remote code execution, denial of service"
    return "Example Corp, Widget Inc"


def _canonical_models():
    keys = [criterion.key for criterion in CRITERIA]
    for key in keys:
        yield Model("any", {key: ("include", SAMPLES[key])})
    for first, second in itertools.combinations(keys, 2):
        uses = {
            first: ("include", SAMPLES[first]),
            second: ("include", SAMPLES[second]),
        }
        yield Model("any", uses)
        yield Model("all", uses)
    for include_key, exclude_key in itertools.product(keys[:6], keys[6:]):
        yield Model(
            "any",
            {
                include_key: ("include", SAMPLES[include_key]),
                exclude_key: ("exclude", SAMPLES[exclude_key]),
            },
        )
        yield Model(
            "all",
            {
                include_key: ("include", SAMPLES[include_key]),
                exclude_key: ("exclude", SAMPLES[exclude_key]),
            },
        )
    yield Model(
        "any",
        {
            "kev": ("include", "cisa"),
            "cvss_min": ("include", 9.0),
            "vendor": ("exclude", ("Example Corp",)),
            "status": ("exclude", "rejected"),
        },
    )
    yield Model(
        "all",
        {
            "vendor": ("include", ("Example Corp",)),
            "product": ("include", ("Widget",)),
            "cwe": ("exclude", ("CWE-79", "CWE-80")),
        },
    )


def test_criteria_cover_every_condition_schema_key():
    assert len(CRITERIA) == len(CONDITION_SCHEMA)
    keys = [criterion.key for criterion in CRITERIA]
    assert len(keys) == len(set(keys))
    assert set(keys) == set(CONDITION_SCHEMA)
    assert set(CRITERIA_BY_KEY) == set(CONDITION_SCHEMA)
    for criterion in CRITERIA:
        assert CRITERIA_BY_KEY[criterion.key] is criterion
        assert criterion.label
        assert criterion.help
        schema = CONDITION_SCHEMA[criterion.key]
        assert criterion.kind == schema["kind"]
        if criterion.kind == "enum":
            assert tuple(value for value, _ in criterion.choices) == tuple(
                schema["choices"]
            )
            assert all(label for _, label in criterion.choices)
        else:
            assert criterion.choices == ()
        if criterion.kind == "number":
            assert criterion.minimum == schema["minimum"]
            assert criterion.maximum == schema["maximum"]
            assert criterion.step
        else:
            assert criterion.minimum is None
            assert criterion.maximum is None
            assert criterion.step is None


def test_every_schema_example_and_documented_condition_classifies():
    for key, schema in CONDITION_SCHEMA.items():
        raw = {key: schema["example"]}
        result = read_condition(raw)
        assert result.reason is None, key
        assert result.model is not None
        assert result.model.uses[key][0] == "include"
        assert parse_condition(from_model(result.model))
    for raw, reason in DOC_CONDITIONS:
        result = read_condition(raw)
        assert result.reason == reason, raw
        if reason is None:
            assert result.model is not None
        else:
            assert result.model is None


def test_leaf_and_flat_groups_map_to_models():
    assert to_model({"kev": "cisa"}) == Model(
        "any", {"kev": ("include", "cisa")}
    )
    assert to_model(
        {"any": [{"cvss_min": 9.0}, {"epss_min": 0.5}]}
    ) == Model(
        "any",
        {"cvss_min": ("include", 9.0), "epss_min": ("include", 0.5)},
    )
    assert to_model(
        {"all": [{"cvss_min": 9}, {"epss_min": 0.5}]}
    ) == Model(
        "all",
        {"cvss_min": ("include", 9.0), "epss_min": ("include", 0.5)},
    )
    assert to_model({"vendor": ["Example Corp"]}) == Model(
        "any", {"vendor": ("include", ("Example Corp",))}
    )


def test_exclusion_shapes_map_to_models():
    assert to_model(
        {"all": [{"cvss_min": 9}, {"not": {"vendor": ["examplecorp"]}}]}
    ) == Model(
        "any",
        {
            "cvss_min": ("include", 9.0),
            "vendor": ("exclude", ("examplecorp",)),
        },
    )
    assert to_model(
        {
            "all": [
                {"all": [{"kev": "cisa"}, {"epss_min": 0.5}]},
                {"not": {"status": "rejected"}},
            ]
        }
    ) == Model(
        "all",
        {
            "kev": ("include", "cisa"),
            "epss_min": ("include", 0.5),
            "status": ("exclude", "rejected"),
        },
    )
    assert to_model(
        {
            "all": [
                {"kev": "cisa"},
                {"not": {"any": [{"vendor": ["A"]}, {"product": ["B"]}]}},
            ]
        }
    ) == Model(
        "any",
        {
            "kev": ("include", "cisa"),
            "vendor": ("exclude", ("A",)),
            "product": ("exclude", ("B",)),
        },
    )


def test_match_mode_is_normalised_when_only_one_criterion_is_included():
    single = Model("all", {"kev": ("include", "cisa")})
    assert single.join == "any"
    assert single == Model("any", {"kev": ("include", "cisa")})
    with_exclude = Model(
        "all",
        {
            "kev": ("include", "cisa"),
            "status": ("exclude", "rejected"),
        },
    )
    assert with_exclude.join == "any"
    pair = Model(
        "all",
        {
            "kev": ("include", "cisa"),
            "status": ("include", "published"),
        },
    )
    assert pair.join == "all"


def test_from_model_composes_canonical_conditions():
    assert from_model(Model("any", {"kev": ("include", "cisa")})) == {
        "kev": "cisa"
    }
    assert from_model(
        Model(
            "any",
            {"kev": ("include", "cisa"), "cvss_min": ("include", 9.0)},
        )
    ) == {"any": [{"kev": "cisa"}, {"cvss_min": 9.0}]}
    assert from_model(
        Model(
            "all",
            {"cwe": ("include", ("CWE-79", "CWE-80"))},
        )
    ) == {"cwe": ["CWE-79", "CWE-80"]}
    assert from_model(
        Model(
            "all",
            {
                "cvss_min": ("include", 9.0),
                "vendor": ("exclude", ("examplecorp",)),
            },
        )
    ) == {
        "all": [
            {"cvss_min": 9.0},
            {"not": {"vendor": ["examplecorp"]}},
        ]
    }
    assert from_model(
        Model(
            "any",
            {
                "kev": ("include", "cisa"),
                "cvss_min": ("include", 9.0),
                "vendor": ("exclude", ("A",)),
                "product": ("exclude", ("B",)),
            },
        )
    ) == {
        "all": [
            {"any": [{"kev": "cisa"}, {"cvss_min": 9.0}]},
            {"not": {"any": [{"vendor": ["A"]}, {"product": ["B"]}]}},
        ]
    }
    assert from_model(
        Model(
            "all",
            {
                "vendor": ("include", ("Example Corp",)),
                "product": ("include", ("Widget",)),
                "cwe": ("exclude", ("CWE-79",)),
            },
        )
    ) == {
        "all": [
            {"all": [{"vendor": ["Example Corp"]}, {"product": ["Widget"]}]},
            {"not": {"cwe": ["CWE-79"]}},
        ]
    }


def test_from_model_rejects_empty_or_invalid_models():
    with pytest.raises(ValueError):
        from_model(Model("any", {"kev": ("exclude", "cisa")}))
    with pytest.raises(ValueError):
        from_model(
            Model(
                "sideways",
                {
                    "kev": ("include", "cisa"),
                    "status": ("include", "published"),
                },
            )
        )
    with pytest.raises(ValueError):
        from_model(Model("any", {"not_a_key": ("include", "x")}))
    with pytest.raises(ValueError):
        from_model(Model("any", {"kev": ("maybe", "cisa")}))
    with pytest.raises(ValueError):
        from_model(Model("any", {"kev": ("include", "bogus")}))
    with pytest.raises(ValueError):
        from_model(Model("any", {"cvss_min": ("include", True)}))
    with pytest.raises(ValueError):
        from_model(Model("any", {"vendor": ("include", ())}))
    with pytest.raises(ValueError):
        from_model(Model("any", {"vendor": ("include", (1,))}))


def test_models_round_trip_through_the_canonical_condition():
    models = list(_canonical_models())
    assert len(models) > 100
    for model in models:
        raw = from_model(model)
        assert _condition_depth(raw) <= MAX_DEPTH
        parse_condition(raw)
        result = read_condition(raw)
        assert result.reason is None, (model, raw)
        assert result.model == model, (model, raw, result.model)


def test_model_equality_ignores_toml_formatting_and_value_spelling():
    assert to_model({"cvss_min": 9}) == to_model({"cvss_min": 9.0})
    assert to_model({"kev": "CISA"}) == to_model({"kev": "cisa"})
    assert to_model({"vendor": ["Example", "example"]}) == to_model(
        {"vendor": ["Example"]}
    )
    assert to_model({"cwe": ["79"]}) == to_model({"cwe": ["CWE-79"]})
    assert to_model({"any": [{"cvss_min": 9}, {"epss_min": 0.5}]}) == to_model(
        {"any": [{"cvss_min": 9.0}, {"epss_min": 0.50}]}
    )


@pytest.mark.parametrize(
    "raw, reason",
    [
        ({"kev": "cisa", "cvss_min": 9}, REASON_MULTIPLE_KEYS),
        (
            {"any": [{"kev": "cisa", "cvss_min": 9}, {"status": "published"}]},
            REASON_MULTIPLE_KEYS,
        ),
        (
            {"any": [{"kev": "cisa"}, {"kev": "eu"}]},
            REASON_REPEATED,
        ),
        (
            {"all": [{"kev": "cisa"}, {"not": {"kev": "eu"}}]},
            REASON_REPEATED,
        ),
        (
            {"all": [{"any": [{"kev": "cisa"}, {"epss_min": 0.5}]},
                     {"vendor": ["Example"]}]},
            REASON_NESTED,
        ),
        ({"not": {"kev": "cisa"}}, REASON_NESTED),
        (
            {"all": [{"kev": "cisa"},
                     {"not": {"all": [{"vendor": ["A"]}, {"product": ["B"]}]}}]},
            REASON_NESTED,
        ),
        (
            {"any": [{"any": [{"kev": "cisa"}, {"epss_min": 0.5}]},
                     {"vendor": ["Example"]}]},
            REASON_NESTED,
        ),
        (
            {"cvss_min": {"score": 9.0, "versions": ["4.0"]}},
            REASON_QUALIFIED,
        ),
        (
            {"cvss_max": {"score": 7.0, "versions": ["4.0"],
                          "providers": ["cna"]}},
            REASON_QUALIFIED,
        ),
        ({"vendor": ["Example, Inc."]}, REASON_COMMA),
        ({"keyword": ["remote, code"]}, REASON_COMMA),
        ({"cna": ["Example, Inc."]}, REASON_COMMA),
        ({"product": ["Widget", "Gadget, Pro"]}, REASON_COMMA),
        ({"not_a_key": 1}, REASON_UNREADABLE),
        ({}, REASON_UNREADABLE),
        ("not a table", REASON_UNREADABLE),
        ({"kev": ["cisa"]}, REASON_UNREADABLE),
        ({"cvss_min": "high"}, REASON_UNREADABLE),
    ],
)
def test_every_non_representable_class_opens_in_text_mode(raw, reason):
    result = read_condition(raw)
    assert result.model is None
    assert result.reason == reason
    assert to_model(raw) is None


def test_text_mode_reasons_are_fixed_one_line_copy():
    for reason in REASONS:
        assert reason
        assert "\n" not in reason
        assert reason.endswith(".")
        for key in CONDITION_SCHEMA:
            assert key not in reason
        for word in BANNED_WORDS:
            assert word not in reason.casefold()


@pytest.mark.parametrize(
    "original",
    [
        {"kev": "cisa"},
        {"any": [{"cvss_min": 9.0}, {"epss_min": 0.5}]},
        {"all": [{"kev": "cisa"}]},
        {"all": [{"vendor": ["Example Corp"]},
                 {"not": {"product": ["Widget"]}}]},
        {"all": [{"all": [{"kev": "cisa"}, {"epss_min": 0.5}]},
                 {"not": {"any": [{"vendor": ["A"]}, {"status": "rejected"}]}}]},
    ],
)
def test_noop_save_keeps_the_stored_condition_and_rule_hash(original):
    model = to_model(original)
    assert model is not None
    saved = keep_original_condition(original, model)
    assert saved == original
    assert saved is not original
    assert condition_payload(parse_condition(saved)) == condition_payload(
        parse_condition(original)
    )
    assert rule_hash(_rule(saved)) == rule_hash(_rule(original))
    # An unrelated rule edit keeps the same condition and therefore the same hash.
    unrelated = Rule(
        name="renamed rule",
        condition=parse_condition(saved),
        channels=("slack",),
    )
    assert rule_hash(unrelated) == rule_hash(_rule(original))


def test_keep_original_returns_a_deep_copy():
    original = {"any": [{"vendor": ["Example"]}, {"product": ["Widget"]}]}
    saved = keep_original_condition(original, to_model(original))
    saved["any"][0]["vendor"].append("Other")
    assert original == {"any": [{"vendor": ["Example"]}, {"product": ["Widget"]}]}


def test_changed_model_builds_a_new_condition_and_hash():
    original = {"cvss_min": 9.0}
    model = Model("any", {"cvss_min": ("include", 8.0)})
    saved = keep_original_condition(original, model)
    assert saved == {"cvss_min": 8.0}
    assert rule_hash(_rule(saved)) != rule_hash(_rule(original))


def test_unrepresentable_original_is_replaced_by_the_submitted_model():
    original = {"cvss_min": {"score": 9.0, "versions": ["4.0"]}}
    model = Model("any", {"cvss_min": ("include", 8.0)})
    assert keep_original_condition(original, model) == {"cvss_min": 8.0}


def test_keep_original_requires_an_include():
    with pytest.raises(ValueError):
        keep_original_condition(
            {"kev": "cisa"}, Model("any", {"kev": ("exclude", "cisa")})
        )


def test_build_model_accepts_every_criterion():
    uses = {criterion.key: "include" for criterion in CRITERIA}
    values = {criterion.key: _sample_text(criterion) for criterion in CRITERIA}
    result = build_model("all", uses, values)
    assert result.ok
    assert result.errors == ()
    assert result.model is not None
    assert result.model.join == "all"
    for criterion in CRITERIA:
        assert result.model.uses[criterion.key][0] == "include"
        assert result.error_for(criterion.key) is None
    assert result.model.uses["kev"] == ("include", "cisa")
    assert result.model.uses["cvss_min"] == ("include", 9.0)
    assert result.model.uses["epss_min"] == ("include", 0.5)
    assert result.model.uses["vendor"] == (
        "include",
        ("Example Corp", "Widget Inc"),
    )
    assert result.model.uses["cwe"] == (
        "include",
        ("CWE-79", "CWE-80"),
    )


def test_build_model_normalises_values():
    result = build_model(
        "any",
        {
            "kev": "include",
            "cvss_min": "include",
            "vendor": "include",
            "cwe": "include",
        },
        {
            "kev": "CISA",
            "cvss_min": "9",
            "vendor": "Example, example, Widget",
            "cwe": "79, cwe-79, CWE-80",
        },
    )
    assert result.ok
    assert result.model.uses["kev"] == ("include", "cisa")
    assert result.model.uses["cvss_min"] == ("include", 9.0)
    assert result.model.uses["vendor"] == ("include", ("Example", "Widget"))
    assert result.model.uses["cwe"] == (
        "include",
        ("CWE-79", "CWE-80"),
    )


def test_build_model_keeps_excludes_and_the_match_mode():
    result = build_model(
        "any",
        {
            "kev": "include",
            "cvss_min": "include",
            "status": "exclude",
        },
        {
            "kev": "cisa",
            "cvss_min": "9.0",
            "status": "rejected",
        },
    )
    assert result.ok
    assert result.model == Model(
        "any",
        {
            "kev": ("include", "cisa"),
            "cvss_min": ("include", 9.0),
            "status": ("exclude", "rejected"),
        },
    )
    assert describe(result.model) == (
        "Alert when ANY of: on the CISA list; "
        "severity score at least 9.0. "
        "Never alert when: status is Rejected."
    )


@pytest.mark.parametrize(
    "join, uses, values, field, message",
    [
        (
            "any",
            {"kev": "include"},
            {"kev": ""},
            "kev",
            "On a list of flaws known to be exploited: choose one of the options.",
        ),
        (
            "any",
            {"cvss_min": "include"},
            {"cvss_min": ""},
            "cvss_min",
            "Severity score is at least: enter a number from 0 to 10.",
        ),
        (
            "any",
            {"cvss_min": "include"},
            {"cvss_min": "eleven"},
            "cvss_min",
            "Severity score is at least: enter a number from 0 to 10.",
        ),
        (
            "any",
            {"epss_min": "include"},
            {"epss_min": "1.1"},
            "epss_min",
            "Exploitation chance is at least: enter a number from 0 to 1.",
        ),
        (
            "any",
            {"epss_min": "include"},
            {"epss_min": "nan"},
            "epss_min",
            "Exploitation chance is at least: enter a number from 0 to 1.",
        ),
        (
            "any",
            {"vendor": "include"},
            {"vendor": " , "},
            "vendor",
            "Vendor is one of: enter at least one value, separated by commas.",
        ),
        (
            "any",
            {"cwe": "include"},
            {"cwe": "not-a-cwe"},
            "cwe",
            "Weakness type is: use a CWE number such as 79 or CWE-787.",
        ),
        (
            "any",
            {"vendor": "include"},
            {"vendor": ", ".join(f"vendor-{n}" for n in range(MAX_LIST_ITEMS + 1))},
            "vendor",
            f"Vendor is one of: enter at most {MAX_LIST_ITEMS} values, "
            "separated by commas.",
        ),
        (
            "any",
            {"keyword": "include"},
            {"keyword": "x" * (MAX_STRING + 1)},
            "keyword",
            f"Description contains: each value must be at most {MAX_STRING} "
            "characters.",
        ),
        (
            "any",
            {"kev": "maybe"},
            {"kev": "cisa"},
            "kev",
            "On a list of flaws known to be exploited: choose one of the options.",
        ),
        (
            "sideways",
            {"kev": "include"},
            {"kev": "cisa"},
            BUILD_FIELD_JOIN,
            "Match: choose one of the options.",
        ),
        (
            "any",
            {"kev": ""},
            {},
            BUILD_FIELD_CRITERIA,
            NO_CRITERIA_MESSAGE,
        ),
        (
            "any",
            {"kev": "exclude"},
            {"kev": "eu"},
            BUILD_FIELD_CRITERIA,
            NO_CRITERIA_MESSAGE,
        ),
        (
            5,
            {"kev": "include"},
            {"kev": "cisa"},
            BUILD_FIELD_JOIN,
            "Match: choose one of the options.",
        ),
        (
            "any",
            {"kev": 5},
            {"kev": "cisa"},
            "kev",
            "On a list of flaws known to be exploited: choose one of the options.",
        ),
        (
            "any",
            {"kev": ["include"]},
            {"kev": "cisa"},
            "kev",
            "On a list of flaws known to be exploited: choose one of the options.",
        ),
        (
            "any",
            {"vendor": "include"},
            {"vendor": ["A", "B"]},
            "vendor",
            "Vendor is one of: enter at least one value, separated by commas.",
        ),
        (
            "any",
            {"cvss_min": "include"},
            {"cvss_min": 9.5},
            "cvss_min",
            "Severity score is at least: enter a number from 0 to 10.",
        ),
    ],
)
def test_build_model_errors_are_field_keyed_and_do_not_echo(
    join, uses, values, field, message
):
    result = build_model(join, uses, values)
    assert not result.ok
    assert result.model is None
    assert result.error_for(field) == message
    for _, actual in result.errors:
        assert actual
        assert "vendor-" not in actual
        assert "xxxxx" not in actual


def test_build_model_unknown_criterion_is_a_bad_request():
    with pytest.raises(ValueError):
        build_model("any", {"forged": "include"}, {})
    with pytest.raises(ValueError):
        build_model("any", {}, {"forged": "value"})


def test_build_result_error_for_unknown_field_is_none():
    result = build_model("any", {"kev": ""}, {})
    assert result.error_for("nope") is None


def test_build_model_rejects_underscores_in_numbers():
    result = build_model("any", {"cvss_min": "include"}, {"cvss_min": "1_0"})
    assert not result.ok
    assert result.model is None
    assert result.error_for("cvss_min") == (
        "Severity score is at least: enter a number from 0 to 10."
    )


def test_build_model_normalises_negative_zero():
    result = build_model("any", {"cvss_min": "include"}, {"cvss_min": "-0"})
    assert result.ok
    value = result.model.uses["cvss_min"][1]
    assert value == 0.0
    assert math.copysign(1.0, value) == 1.0
    assert describe(result.model) == "Alert when: severity score at least 0.0."
    assert describe(Model("any", {"cvss_min": ("include", -0.0)})) == (
        "Alert when: severity score at least 0.0."
    )


def test_describe_single_include_and_all_mode():
    assert describe(Model("any", {"cvss_min": ("include", 9.0)})) == (
        "Alert when: severity score at least 9.0."
    )
    assert describe(
        Model(
            "all",
            {"kev": ("include", "cisa"), "cvss_min": ("include", 9.0)},
        )
    ) == (
        "Alert when ALL of: on the CISA list; severity score at least 9.0."
    )
    assert describe(
        Model(
            "any",
            {
                "kev": ("include", "cisa"),
                "vendor": ("exclude", ("Example Corp",)),
                "product": ("exclude", ("Widget",)),
            },
        )
    ) == (
        "Alert when: on the CISA list. "
        "Never alert when any of: vendor is Example Corp; product is Widget."
    )


def test_describe_uses_plain_words_for_every_criterion():
    uses = {criterion.key: "include" for criterion in CRITERIA}
    values = {criterion.key: _sample_text(criterion) for criterion in CRITERIA}
    model = build_model("any", uses, values).model
    text = describe(model)
    assert "Alert when ANY of: " in text
    assert "_" not in text
    assert "\n" not in text
    assert "on the CISA list" in text
    assert "exploit code exists or is active" in text
    assert "severity score at least 9.0" in text
    assert "severity score at most 10.0" in text
    assert "exploitation chance at least 0.5" in text
    assert "vendor is one of Example Corp, Widget Inc" in text
    assert "product is one of Example Corp, Widget Inc" in text
    assert (
        "description contains any of remote code execution, denial of service"
        in text
    )
    assert "weakness type is one of CWE-79, CWE-80" in text
    assert "reported by one of Example Corp, Widget Inc" in text
    assert "status is Published" in text


def test_describe_shows_exact_score_thresholds():
    assert describe(
        build_model("any", {"cvss_min": "include"}, {"cvss_min": "9.55"}).model
    ) == "Alert when: severity score at least 9.55."
    assert describe(
        build_model("any", {"cvss_max": "include"}, {"cvss_max": "9.55"}).model
    ) == "Alert when: severity score at most 9.55."
    assert describe(
        build_model(
            "any", {"epss_min": "include"}, {"epss_min": "0.1234567"}
        ).model
    ) == "Alert when: exploitation chance at least 0.1234567."


def test_describe_shows_tiny_epss_values_in_decimal():
    assert describe(Model("any", {"epss_min": ("include", 1e-05)})) == (
        "Alert when: exploitation chance at least 0.00001."
    )
    result = build_model("any", {"epss_min": "include"}, {"epss_min": "0.00001"})
    assert result.ok
    assert describe(result.model) == (
        "Alert when: exploitation chance at least 0.00001."
    )


def test_public_copy_never_uses_banned_words():
    texts = [MATCH_HELP, EXCLUDE_HELP, NO_CRITERIA_MESSAGE]
    texts.extend(label for _, label in USE_OPTIONS)
    texts.extend(label for _, label in MATCH_OPTIONS)
    for criterion in CRITERIA:
        texts.extend([criterion.label, criterion.help])
        texts.extend(label for _, label in criterion.choices)
    texts.extend(REASONS)
    texts.append(describe(Model("any", {"kev": ("include", "cisa")})))
    for text in texts:
        lowered = text.casefold()
        for word in BANNED_WORDS:
            assert word not in lowered, (word, text)


@pytest.mark.parametrize("control", ["\r", "\n", "\t", "\0", "\x7f", "\x85"])
@pytest.mark.parametrize("as_list", [True, False])
def test_control_characters_force_text_mode(control, as_list):
    # The loader can strip controls at the edges before the builder sees them.
    raw = {"keyword": [f"alpha{control}beta"]} if as_list else {"kev": f"cisa{control}"}
    read = read_condition(raw)
    assert read.model is None
    assert read.reason == "This rule contains a line break or control character. Edit it as text."
