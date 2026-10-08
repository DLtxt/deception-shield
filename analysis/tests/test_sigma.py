"""The Sigma engine: matching semantics, conditions, validation and portability."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from deception_shield.sigma import (
    SigmaError,
    load_rules,
    parse_rule,
    pipeline_fields,
    portability_problems,
)

RULE_ID = "6f1c3a52-3c55-4b6e-9a3e-9d1f5a1e0c11"


def document(detection: str, **overrides) -> dict:
    base = {
        "title": "Test rule",
        "id": RULE_ID,
        "status": "test",
        "level": "high",
        "logsource": {"product": "cowrie"},
        "tags": ["attack.execution", "attack.t1059.004"],
        "detection": yaml.safe_load(detection),
    }
    base.update(overrides)
    return base


def rule(detection: str, **overrides):
    doc = document(detection, **overrides)
    return parse_rule(doc, text=yaml.safe_dump(doc))


def matches(detection: str, value: str, field: str = "input") -> bool:
    return rule(detection).matches({field: value})


class TestValueMatching:
    def test_plain_values_match_the_whole_field_case_insensitively(self) -> None:
        detection = "sel:\n  input: 'uname -a'\ncondition: sel"
        assert matches(detection, "UNAME -A")
        assert not matches(detection, "uname -a; id")

    @pytest.mark.parametrize(
        ("modifier", "value", "expected"),
        [
            ("contains", "cd /tmp; wget x", True),
            ("contains", "curl x", False),
            ("startswith", "wget http://x", True),
            ("startswith", "cd /tmp; wget x", False),
            ("endswith", "busybox wget", True),
            ("endswith", "wget x", False),
        ],
    )
    def test_position_modifiers(self, modifier: str, value: str, expected: bool) -> None:
        assert matches(f"sel:\n  input|{modifier}: wget\ncondition: sel", value) is expected

    def test_wildcards_inside_values(self) -> None:
        detection = "sel:\n  input|contains: '/proc/cpuinfo*wc -l'\ncondition: sel"
        assert matches(detection, "cat /proc/cpuinfo | grep name | wc -l")
        assert not matches(detection, "cat /proc/cpuinfo")

    def test_question_mark_matches_one_character(self) -> None:
        assert matches("sel:\n  input: 'sh?'\ncondition: sel", "sh1")
        assert not matches("sel:\n  input: 'sh?'\ncondition: sel", "sh12")

    def test_escaped_wildcards_are_literal(self) -> None:
        detection = "sel:\n  input|contains: 'echo \\*'\ncondition: sel"
        assert matches(detection, "echo *")
        assert not matches(detection, "echo hello")

    def test_a_backslash_before_anything_else_is_literal(self) -> None:
        """\\x7f in a rule means a backslash followed by x7f, not a control character."""
        detection = "sel:\n  input|contains: '\\x7f\\x45'\ncondition: sel"
        assert matches(detection, r"echo -ne '\x7f\x45' > .d")
        assert not matches(detection, "echo -ne '\x7f\x45' > .d")

    def test_a_doubled_backslash_is_one_backslash(self) -> None:
        assert matches("sel:\n  input|contains: 'a\\\\b'\ncondition: sel", r"a\b")

    def test_cased_makes_matching_case_sensitive(self) -> None:
        detection = "sel:\n  input|contains|cased: Mem\ncondition: sel"
        assert matches(detection, "grep Mem")
        assert not matches(detection, "grep mem")

    def test_a_list_of_values_is_an_or(self) -> None:
        detection = "sel:\n  input|contains: [wget, curl]\ncondition: sel"
        assert matches(detection, "curl x") and matches(detection, "wget x")

    def test_all_turns_the_list_into_an_and(self) -> None:
        detection = "sel:\n  input|contains|all: [wget, chmod]\ncondition: sel"
        assert matches(detection, "wget x; chmod +x x")
        assert not matches(detection, "wget x")

    def test_a_mapping_is_an_and_of_its_fields(self) -> None:
        r = rule("sel:\n  eventid: cowrie.command.input\n  input|contains: wget\ncondition: sel")
        assert r.matches({"eventid": "cowrie.command.input", "input": "wget x"})
        assert not r.matches({"eventid": "cowrie.login.success", "input": "wget x"})

    def test_a_list_of_mappings_is_an_or(self) -> None:
        r = rule("sel:\n  - input: a\n  - username: root\ncondition: sel")
        assert r.matches({"input": "a"}) and r.matches({"username": "root"})
        assert not r.matches({"input": "b", "username": "admin"})

    def test_null_matches_a_missing_or_empty_field(self) -> None:
        r = rule("sel:\n  username: null\ncondition: sel")
        assert r.matches({}) and r.matches({"username": ""})
        assert not r.matches({"username": "root"})

    def test_exists(self) -> None:
        present = rule("sel:\n  username|exists: true\ncondition: sel")
        absent = rule("sel:\n  username|exists: false\ncondition: sel")
        assert present.matches({"username": "root"}) and not present.matches({})
        assert absent.matches({}) and not absent.matches({"username": "root"})

    def test_missing_fields_never_match_a_value(self) -> None:
        assert not rule("sel:\n  input|contains: wget\ncondition: sel").matches({})

    def test_dotted_fields_reach_into_nested_events(self) -> None:
        r = rule("sel:\n  process.command_line|contains: wget\ncondition: sel")
        assert r.matches({"process": {"command_line": "wget x"}})


class TestRegularExpressions:
    """Expressions match the whole value, the way Elasticsearch matches them."""

    def test_an_expression_must_cover_the_whole_value(self) -> None:
        assert not matches("sel:\n  input|re: 'wget .*'\ncondition: sel", "cd /tmp; wget x")
        assert matches("sel:\n  input|re: '.*wget .*'\ncondition: sel", "cd /tmp; wget x")

    def test_an_optional_prefix_anchors_to_a_command_boundary(self) -> None:
        detection = "sel:\n  input|re: '(.*[ ;])?crontab +[^- ][^ ]*.*'\ncondition: sel"
        assert matches(detection, "crontab /tmp/x")
        assert matches(detection, "cd /tmp; crontab .c")
        assert not matches(detection, "cp /etc/crontab /tmp/b")

    def test_dot_matches_newlines_as_lucene_does(self) -> None:
        assert matches("sel:\n  input|re: '.*wget.*'\ncondition: sel", "cd /tmp\nwget x\nsh x")

    def test_expressions_are_case_sensitive_unless_flagged(self) -> None:
        assert not matches("sel:\n  input|re: '.*WGET.*'\ncondition: sel", "wget x")
        assert matches("sel:\n  input|re|i: '.*WGET.*'\ncondition: sel", "wget x")

    def test_an_invalid_expression_is_rejected(self) -> None:
        with pytest.raises(SigmaError, match="invalid regular expression"):
            rule("sel:\n  input|re: '(unclosed'\ncondition: sel")


class TestConditions:
    EVENTS = {"a": {"input": "a"}, "b": {"input": "b"}, "c": {"input": "c"}}

    def build(self, condition: str):
        return rule(
            f"sel_a:\n  input: a\nsel_b:\n  input: b\n_helper:\n  input: c\ncondition: {condition}"
        )

    def test_not_binds_tighter_than_and_which_binds_tighter_than_or(self) -> None:
        r = self.build("sel_a or sel_b and not _helper")
        assert r.matches(self.EVENTS["a"]) and r.matches(self.EVENTS["b"])
        assert not r.matches(self.EVENTS["c"])

    def test_parentheses_group(self) -> None:
        r = self.build("(sel_a or sel_b) and not _helper")
        assert r.matches(self.EVENTS["b"]) and not r.matches(self.EVENTS["c"])

    def test_one_of_a_pattern(self) -> None:
        r = self.build("1 of sel_* or _helper")
        assert all(r.matches(e) for e in self.EVENTS.values())

    def test_all_of_a_pattern(self) -> None:
        r = rule(
            "sel_a:\n  input|contains: a\nsel_b:\n  input|contains: b\ncondition: all of sel_*"
        )
        assert r.matches({"input": "ab"}) and not r.matches({"input": "a"})

    def test_them_leaves_out_underscore_helpers(self) -> None:
        r = self.build("1 of them or _helper")
        assert r.matches(self.EVENTS["c"])
        with pytest.raises(SigmaError, match="not used"):
            self.build("1 of them")

    def test_a_list_of_conditions_is_an_or(self) -> None:
        r = rule("sel_a:\n  input: a\nsel_b:\n  input: b\ncondition: [sel_a, sel_b]")
        assert r.matches({"input": "a"}) and r.matches({"input": "b"})


class TestRejection:
    """Anything the engine cannot honour fails loudly instead of matching nothing."""

    @pytest.mark.parametrize(
        ("detection", "message"),
        [
            ("sel:\n  input|base64offset|contains: x\ncondition: sel", "unsupported modifier"),
            ("sel:\n  input|contains|startswith: x\ncondition: sel", "mutually exclusive"),
            ("sel:\n  input|contains|i: x\ncondition: sel", "apply only to re"),
            ("sel:\n  input|re|contains: x\ncondition: sel", "cannot be combined"),
            ("sel:\n  input|exists: yes please\ncondition: sel", "true or false"),
            ("sel:\n  input: [null, x]\ncondition: sel", "null stands alone"),
            ("sel:\n  - wget\n  - curl\ncondition: sel", "keyword searches"),
            ("sel:\n  '|contains': x\ncondition: sel", "keyword searches"),
            ("sel:\n  input: x\ncondition: sel | count() > 5", "aggregations"),
            ("sel:\n  input: x\ntimeframe: 5m\ncondition: sel", "timeframe"),
            ("sel:\n  input: x\ncondition: other", "undefined search identifier"),
            ("sel:\n  input: x\nspare:\n  input: y\ncondition: sel", "not used"),
            ("sel:\n  input: x\ncondition: sel and (sel", "ends unexpectedly"),
            ("sel:\n  input: x\ncondition: 1 of nothing_*", "matches no search identifier"),
            ("sel:\n  input: x\ncondition: sel sel", "unexpected"),
            ("sel:\n  input: x", "condition"),
        ],
    )
    def test_detection_problems(self, detection: str, message: str) -> None:
        with pytest.raises(SigmaError, match=message):
            rule(detection)

    @pytest.mark.parametrize(
        ("overrides", "message"),
        [
            ({"id": "not-a-uuid"}, "UUID"),
            ({"title": ""}, "title"),
            ({"status": "finished"}, "status"),
            ({"level": "severe"}, "level"),
            ({"date": "07/10/2026"}, "YYYY-MM-DD"),
            ({"logsource": {}}, "logsource"),
            ({"tags": ["Attack.T1059"]}, "tags"),
            ({"falsepositives": "none"}, "falsepositives"),
        ],
    )
    def test_metadata_problems(self, overrides: dict, message: str) -> None:
        with pytest.raises(SigmaError, match=message):
            rule("sel:\n  input: x\ncondition: sel", **overrides)

    def test_errors_name_the_rule(self) -> None:
        with pytest.raises(SigmaError, match="^my_rule.yml: "):
            parse_rule({"title": ""}, source="my_rule.yml")


class TestRuleMetadata:
    def test_techniques_and_tactics_are_read_from_tags(self) -> None:
        r = rule(
            "sel:\n  input: x\ncondition: sel",
            tags=[
                "attack.persistence",
                "attack.t1098.004",
                "attack.t1098.004",
                "attack.g0032",
                "cve.2021-44228",
            ],
        )
        assert r.techniques == ("T1098.004",)
        assert r.tactics == ("persistence",)

    def test_logsource_applicability(self) -> None:
        r = rule("sel:\n  input: x\ncondition: sel")
        assert r.applies_to({"product": "cowrie"})
        assert not r.applies_to({"product": "linux", "category": "process_creation"})


def write_rule(directory: Path, name: str, **overrides) -> Path:
    doc = document("sel:\n  input|contains: wget\ncondition: sel", **overrides)
    path = directory / name
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return path


class TestRuleSets:
    def test_loads_a_directory(self, tmp_path: Path) -> None:
        write_rule(tmp_path, "a.yml")
        write_rule(
            tmp_path,
            "b.yml",
            id="0e7a7ffd-5a3c-4f68-9a54-0b1b3e9e4a01",
            title="Other",
            tags=["attack.discovery", "attack.t1082"],
        )
        ruleset = load_rules(tmp_path)
        assert len(ruleset) == 2
        assert ruleset.techniques == ("T1059.004", "T1082")
        assert ruleset.describe() == "2 Sigma rules across 2 ATT&CK techniques"

    def test_sub_techniques_fold_into_their_parent_for_the_count(self, tmp_path: Path) -> None:
        write_rule(tmp_path, "a.yml", tags=["attack.t1098.004"])
        write_rule(
            tmp_path,
            "b.yml",
            id="0e7a7ffd-5a3c-4f68-9a54-0b1b3e9e4a01",
            title="Other",
            tags=["attack.t1098"],
        )
        ruleset = load_rules(tmp_path)
        assert ruleset.parent_techniques == ("T1098",)
        assert (
            ruleset.describe()
            == "2 Sigma rules across 1 ATT&CK technique (2 including sub-techniques)"
        )

    def test_every_problem_is_reported_at_once(self, tmp_path: Path) -> None:
        write_rule(tmp_path, "a.yml", status="bogus")
        write_rule(tmp_path, "b.yml", level="bogus")
        (tmp_path / "c.yml").write_text("title: [unclosed", encoding="utf-8")
        with pytest.raises(SigmaError) as error:
            load_rules(tmp_path)
        assert all(name in str(error.value) for name in ("a.yml", "b.yml", "c.yml"))

    def test_duplicate_ids_and_titles_are_rejected(self, tmp_path: Path) -> None:
        write_rule(tmp_path, "a.yml")
        write_rule(tmp_path, "b.yml")
        with pytest.raises(SigmaError, match="also used by"):
            load_rules(tmp_path)

    def test_a_rule_without_a_technique_cannot_be_counted(self, tmp_path: Path) -> None:
        write_rule(tmp_path, "a.yml", tags=["attack.execution"])
        with pytest.raises(SigmaError, match="ATT&CK technique"):
            load_rules(tmp_path)

    def test_the_fingerprint_follows_the_content(self, tmp_path: Path) -> None:
        path = write_rule(tmp_path, "a.yml")
        before = load_rules(tmp_path).fingerprint
        assert load_rules(tmp_path).fingerprint == before
        path.write_text(path.read_text().replace("wget", "curl"), encoding="utf-8")
        assert load_rules(tmp_path).fingerprint != before

    def test_an_empty_directory_is_an_error(self, tmp_path: Path) -> None:
        with pytest.raises(SigmaError, match="no Sigma rules"):
            load_rules(tmp_path)


class TestPortability:
    FIELDS = frozenset({"eventid", "input"})

    def problems(self, detection: str) -> list[str]:
        return portability_problems(rule(detection), fields=self.FIELDS)

    def test_a_shared_syntax_rule_is_clean(self) -> None:
        assert (
            self.problems("sel:\n  input|re: '(.*[ ;])?wget [^;|\\&]*\\@.*'\ncondition: sel") == []
        )

    @pytest.mark.parametrize(
        ("expression", "message"),
        [
            ("'.*\\bwget\\b.*'", r"\b has no Lucene equivalent"),
            ("'.*wget\\s.*'", r"\s has no Lucene equivalent"),
            ("'^wget.*'", "anchor"),
            ("'.*wget$'", "anchor"),
            ("'.*(?=wget).*'", "lookaround"),
            ("'.*wget.*?'", "lazy"),
            ("'.*user@host.*'", "operator"),
            ("'.*a{,3}.*'", "{0,n}"),
        ],
    )
    def test_lucene_incompatible_syntax(self, expression: str, message: str) -> None:
        problems = self.problems(f"sel:\n  input|re: {expression}\ncondition: sel")
        assert any(message in p for p in problems), problems

    def test_flags_have_no_lucene_form(self) -> None:
        assert any(
            "i flag" in p for p in self.problems("sel:\n  input|re|i: '.*x.*'\ncondition: sel")
        )

    def test_fields_must_be_mapped_by_the_pipeline(self) -> None:
        problems = self.problems("sel:\n  CommandLine|contains: x\ncondition: sel")
        assert any("not mapped" in p for p in problems)

    def test_operators_inside_a_class_must_be_escaped_too(self) -> None:
        assert self.problems("sel:\n  input|re: '.*[;&].*'\ncondition: sel")
        assert not self.problems("sel:\n  input|re: '.*[;\\&].*'\ncondition: sel")

    def test_pipeline_fields_read_every_mapping(self, tmp_path: Path) -> None:
        pipeline = tmp_path / "pipeline.yml"
        pipeline.write_text(
            yaml.safe_dump(
                {
                    "name": "p",
                    "transformations": [
                        {
                            "id": "a",
                            "type": "field_name_mapping",
                            "mapping": {"input": "process.command_line"},
                        },
                        {"id": "b", "type": "add_condition", "conditions": {"x": "y"}},
                        {
                            "id": "c",
                            "type": "field_name_mapping",
                            "mapping": {"eventid": "eventid"},
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        assert pipeline_fields(pipeline) == {"input", "eventid"}
