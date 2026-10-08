"""Sigma rule loading and evaluation.

Session detections are written in Sigma, the vendor neutral rule format, so the
file evaluated here is the same file the standard Sigma toolchain converts for a
SIEM. This module implements the part of the specification those rules use and
rejects the rest loudly. A modifier it did not understand would otherwise match
nothing, and a rule that silently never fires is indistinguishable from a rule
that works and has nothing to catch.

Supported:

- selections, where a mapping is an AND of its fields, a list of mappings is an
  OR, and a list of values is an OR unless ``|all`` is given
- the ``contains``, ``startswith``, ``endswith``, ``all``, ``cased``, ``exists``
  and ``re`` modifiers, the last with its ``i``, ``m`` and ``s`` flags
- ``*`` and ``?`` wildcards with backslash escaping
- conditions combining ``and``, ``or``, ``not``, parentheses, and ``1 of`` or
  ``all of`` over an identifier pattern or ``them``

Matching is case insensitive except for regular expressions and ``cased``
values, as the specification requires.

A regular expression must match the whole value, with ``.`` matching newlines.
The specification leaves anchoring to each backend, and the backend these rules
are converted for, Elasticsearch, anchors. Matching the way it does means a rule
that passes the fixture gate behaves identically once sigma-cli has converted
it; an expression meant to match within a value says so with ``.*``.
"""

from __future__ import annotations

import fnmatch
import hashlib
import re
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, NoReturn

import yaml

Event = Mapping[str, Any]
Matcher = Callable[[Event], bool]

STATUSES = frozenset({"stable", "test", "experimental", "deprecated", "unsupported"})
LEVELS: tuple[str, ...] = ("informational", "low", "medium", "high", "critical")

_TECHNIQUE_TAG = re.compile(r"^attack\.t(\d{4})(?:\.(\d{3}))?$")
# Group and software tags (attack.g0032, attack.s0154) are neither tactics nor
# techniques and must not be counted as either.
_ENTITY_TAG = re.compile(r"^attack\.[gs]\d{4}$")
_TAG = re.compile(r"^[a-z0-9_-]+\.[a-z0-9._-]+$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

_POSITION_MODIFIERS = frozenset({"contains", "startswith", "endswith"})
_REGEX_FLAGS = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}
_MODIFIERS = _POSITION_MODIFIERS | {"all", "cased", "exists", "re"} | set(_REGEX_FLAGS)

_CONDITION_TOKEN = re.compile(r"\(|\)|[^\s()]+")


class SigmaError(ValueError):
    """A rule that cannot be loaded, naming the rule and the reason."""


@dataclass(frozen=True, slots=True)
class SigmaRule:
    """One rule, validated and compiled, ready to match events."""

    id: str
    title: str
    status: str
    level: str
    description: str
    author: str
    tags: tuple[str, ...]
    logsource: Mapping[str, str]
    falsepositives: tuple[str, ...]
    source: str
    text: str = field(repr=False)
    matcher: Matcher = field(repr=False, compare=False)

    @property
    def techniques(self) -> tuple[str, ...]:
        """ATT&CK techniques the rule is tagged with, written as ``T1059.004``."""
        found: list[str] = []
        for tag in self.tags:
            match = _TECHNIQUE_TAG.match(tag)
            if match:
                technique = f"T{match.group(1)}" + (f".{match.group(2)}" if match.group(2) else "")
                if technique not in found:
                    found.append(technique)
        return tuple(found)

    @property
    def tactics(self) -> tuple[str, ...]:
        """ATT&CK tactics the rule is tagged with, such as ``persistence``."""
        return tuple(
            tag.split(".", 1)[1]
            for tag in self.tags
            if tag.startswith("attack.")
            and not _TECHNIQUE_TAG.match(tag)
            and not _ENTITY_TAG.match(tag)
        )

    def applies_to(self, logsource: Mapping[str, str]) -> bool:
        """Whether events from ``logsource`` are what this rule was written for."""
        return all(
            logsource.get(key) == value
            for key, value in self.logsource.items()
            if key in ("product", "category", "service")
        )

    def matches(self, event: Event) -> bool:
        return self.matcher(event)


@dataclass(frozen=True, slots=True)
class RuleSet:
    """Rules loaded together, with a fingerprint of exactly what was loaded.

    The fingerprint covers every rule file's name and bytes, so a report or an
    alert that carries it can be traced to the precise rule set that produced
    it, and an evaluation can be shown to have run against frozen rules.
    """

    rules: tuple[SigmaRule, ...]
    fingerprint: str
    directory: Path | None = None

    def __iter__(self) -> Iterator[SigmaRule]:
        return iter(self.rules)

    def __len__(self) -> int:
        return len(self.rules)

    @property
    def techniques(self) -> tuple[str, ...]:
        """Distinct technique and sub-technique identifiers, as tagged."""
        return tuple(sorted({t for rule in self.rules for t in rule.techniques}))

    @property
    def parent_techniques(self) -> tuple[str, ...]:
        """Distinct techniques with sub-techniques folded into their parent."""
        return tuple(sorted({t.split(".")[0] for t in self.techniques}))

    def applicable(self, logsource: Mapping[str, str]) -> tuple[SigmaRule, ...]:
        return tuple(rule for rule in self.rules if rule.applies_to(logsource))

    def get(self, rule_id: str) -> SigmaRule | None:
        return next((rule for rule in self.rules if rule.id == rule_id), None)

    def describe(self) -> str:
        """Summarise the set the way it is reported: rules across techniques.

        Sub-techniques are folded into their parent for the count, and the
        finer figure is given alongside when the two differ, so the summary
        never counts one technique twice.
        """
        count = len(self.rules)
        rules = f"{count} Sigma rule{'' if count == 1 else 's'}"
        parents, identifiers = len(self.parent_techniques), len(self.techniques)
        noun = "technique" if parents == 1 else "techniques"
        if parents == identifiers:
            return f"{rules} across {parents} ATT&CK {noun}"
        return f"{rules} across {parents} ATT&CK {noun} ({identifiers} including sub-techniques)"


def load_rules(directory: Path | str) -> RuleSet:
    """Load and validate every rule under ``directory``.

    Every problem across every file is collected before raising, so fixing a
    rule set is one round trip rather than one per error.
    """
    root = Path(directory)
    if not root.is_dir():
        raise SigmaError(f"{root}: not a directory of Sigma rules")

    paths = sorted(p for p in root.rglob("*") if p.is_file() and p.suffix in (".yml", ".yaml"))
    if not paths:
        raise SigmaError(f"{root}: no Sigma rules found")

    digest = hashlib.sha256()
    rules: list[SigmaRule] = []
    problems: list[str] = []

    for path in paths:
        relative = path.relative_to(root).as_posix()
        raw = path.read_bytes()
        digest.update(relative.encode("utf-8") + b"\0" + raw + b"\0")

        try:
            text = raw.decode("utf-8")
            document = yaml.safe_load(text)
        except (UnicodeDecodeError, yaml.YAMLError) as exc:
            problems.append(f"{relative}: not a valid YAML document: {exc}")
            continue

        try:
            rule = parse_rule(document, source=relative, text=text)
        except SigmaError as exc:
            problems.append(str(exc))
            continue

        # Not a Sigma requirement but a requirement here: technique coverage is
        # counted from these tags, so an untagged rule could not be accounted for.
        if not rule.techniques:
            problems.append(
                f"{relative}: tag at least one ATT&CK technique, such as attack.t1059.004"
            )
        rules.append(rule)

    for attribute in ("id", "title"):
        owners: dict[str, str] = {}
        for rule in rules:
            value = getattr(rule, attribute)
            if value in owners:
                problems.append(
                    f"{rule.source}: {attribute} {value!r} is also used by {owners[value]}"
                )
            else:
                owners[value] = rule.source

    if problems:
        raise SigmaError("\n".join(problems))
    return RuleSet(tuple(rules), digest.hexdigest(), root)


def pipeline_fields(path: Path | str) -> frozenset[str]:
    """Fields a sigma-cli processing pipeline knows how to map.

    Reads every ``field_name_mapping`` transformation in the pipeline file, so
    the portability check can confirm that each field a rule uses has a
    counterpart in the Elasticsearch index.
    """
    document = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    fields: set[str] = set()
    for transformation in document.get("transformations") or []:
        if transformation.get("type") == "field_name_mapping":
            fields.update(str(name) for name in (transformation.get("mapping") or {}))
    return frozenset(fields)


def portability_problems(rule: SigmaRule, *, fields: frozenset[str] | None = None) -> list[str]:
    """Constructs that would make a rule behave differently in Elasticsearch.

    Each rule is evaluated twice in its life: here, against fixtures and the
    session corpus, and in Elasticsearch once sigma-cli has converted it. Both
    match a regular expression against the whole value, so they agree on every
    expression written in the syntax the two share. This check holds rules to
    that shared syntax:

    - no ``^``, ``$``, lookaround, lazy quantifiers, back references, or the
      ``\\b``, ``\\s``, ``\\d`` and ``\\w`` classes, none of which Lucene has
    - ``@ & ~ < > " #`` escaped, since Lucene reads them as operators
    - none of the ``i``, ``m`` and ``s`` flags, which Lucene has no form for
    - every field one the conversion pipeline maps, when ``fields`` is given
    """
    try:
        document = yaml.safe_load(rule.text) if rule.text else None
    except yaml.YAMLError:
        document = None
    detection = document.get("detection") if isinstance(document, Mapping) else None
    if not isinstance(detection, Mapping):
        return [f"{rule.source}: rule text unavailable for the portability check"]

    problems: list[str] = []
    for name, body in detection.items():
        if name == "condition":
            continue
        selections = body if isinstance(body, list) else [body]
        for selection in selections:
            if not isinstance(selection, Mapping):
                continue
            for spec, value in selection.items():
                field_name, *modifiers = str(spec).split("|")
                where = f"{rule.source}: {name}: {spec}"
                if fields is not None and field_name not in fields:
                    problems.append(
                        f"{where}: field {field_name!r} is not mapped by the conversion pipeline"
                    )
                if "re" not in modifiers:
                    continue
                for flag in sorted(set(modifiers) & set(_REGEX_FLAGS)):
                    problems.append(f"{where}: the {flag} flag has no Lucene equivalent")
                for pattern in value if isinstance(value, list) else [value]:
                    problems.extend(
                        f"{where}: {issue}" for issue in _regex_portability(str(pattern))
                    )
    return problems


def _regex_portability(pattern: str) -> list[str]:
    issues: list[str] = []
    in_class = False
    index = 0
    while index < len(pattern):
        char = pattern[index]
        following = pattern[index + 1 : index + 2]
        if char == "\\":
            if following and (following in "bBsSdDwWAZzG" or following.isdigit()):
                issues.append(f"\\{following} has no Lucene equivalent")
            index += 2
            continue
        if not in_class and char == "[":
            in_class = True
            index += 2 if following == "^" else 1
            continue
        if in_class and char == "]":
            in_class = False
        elif char in '@&~<>"#':
            issues.append(f"escape {char!r}; Lucene reads it as an operator")
        elif not in_class:
            if char in "^$":
                issues.append(f"{char!r} is an anchor, which Lucene does not support")
            elif char == "(" and following == "?":
                issues.append("(?...) groups and lookaround are not supported by Lucene")
            elif char in "*+?" and following == "?":
                issues.append("lazy quantifiers are not supported by Lucene")
            elif char == "{" and following == ",":
                issues.append("write {0,n} rather than {,n} for Lucene")
        index += 1

    # One message per kind of problem is enough to act on.
    return list(dict.fromkeys(issues))


def parse_rule(document: Any, *, source: str = "<rule>", text: str = "") -> SigmaRule:
    """Validate one rule document and compile its detection logic."""

    def fail(reason: str) -> NoReturn:
        raise SigmaError(f"{source}: {reason}")

    if not isinstance(document, Mapping):
        fail("a rule must be a mapping")

    title = document.get("title")
    if not isinstance(title, str) or not title.strip():
        fail("title is required")

    rule_id = str(document.get("id") or "")
    try:
        uuid.UUID(rule_id)
    except ValueError:
        fail(f"id must be a UUID, not {rule_id!r}")

    status = document.get("status")
    if status not in STATUSES:
        fail(f"status must be one of {', '.join(sorted(STATUSES))}")

    level = document.get("level")
    if level not in LEVELS:
        fail(f"level must be one of {', '.join(LEVELS)}")

    # YAML reads an unquoted 2026-10-07 as a date, which is the intended form.
    written = document.get("date")
    if written is not None and not isinstance(written, date) and not _DATE.match(str(written)):
        fail("date must be written YYYY-MM-DD")

    logsource = document.get("logsource")
    if not isinstance(logsource, Mapping) or not any(
        key in logsource for key in ("product", "category", "service")
    ):
        fail("logsource needs at least one of product, category or service")

    tags = document.get("tags") or []
    if not isinstance(tags, list) or not all(isinstance(t, str) and _TAG.match(t) for t in tags):
        fail("tags must be a list of lowercase namespace.value strings")

    falsepositives = document.get("falsepositives") or []
    if not isinstance(falsepositives, list) or not all(isinstance(f, str) for f in falsepositives):
        fail("falsepositives must be a list of strings")

    return SigmaRule(
        id=rule_id,
        title=title.strip(),
        status=status,
        level=level,
        description=str(document.get("description") or "").strip(),
        author=str(document.get("author") or "").strip(),
        tags=tuple(tags),
        logsource={str(k): str(v) for k, v in logsource.items()},
        falsepositives=tuple(falsepositives),
        source=source,
        text=text,
        matcher=_compile_detection(document.get("detection"), fail),
    )


# ------------------------------------------------------------------ detection


def _any_of(matchers: Sequence[Matcher]) -> Matcher:
    return lambda event: any(m(event) for m in matchers)


def _all_of(matchers: Sequence[Matcher]) -> Matcher:
    return lambda event: all(m(event) for m in matchers)


def _negate(matcher: Matcher) -> Matcher:
    return lambda event: not matcher(event)


def _compile_detection(detection: Any, fail: Callable[[str], NoReturn]) -> Matcher:
    if not isinstance(detection, Mapping):
        fail("detection must be a mapping")
    if "timeframe" in detection:
        fail("timeframe belongs to correlation rules, which are not supported")

    condition = detection.get("condition")
    conditions = [condition] if isinstance(condition, str) else condition
    if (
        not isinstance(conditions, list)
        or not conditions
        or not all(isinstance(c, str) and c.strip() for c in conditions)
    ):
        fail("detection.condition must be a string or a list of strings")

    searches = {
        str(name): _compile_search(str(name), body, fail)
        for name, body in detection.items()
        if name != "condition"
    }
    if not searches:
        fail("detection defines no search identifiers")

    used: set[str] = set()
    compiled = [_compile_condition(text, searches, used, fail) for text in conditions]

    # An identifier the condition never reaches is almost always a typo in the
    # condition, which would otherwise leave part of the rule silently inert.
    unused = sorted(set(searches) - used)
    if unused:
        fail(f"search identifiers not used by the condition: {', '.join(unused)}")

    return compiled[0] if len(compiled) == 1 else _any_of(compiled)


def _compile_search(name: str, body: Any, fail: Callable[[str], NoReturn]) -> Matcher:
    if isinstance(body, Mapping):
        return _compile_selection(name, body, fail)
    if isinstance(body, list) and body and all(isinstance(item, Mapping) for item in body):
        return _any_of([_compile_selection(name, item, fail) for item in body])
    if isinstance(body, list):
        fail(f"{name}: keyword searches are not supported; match a named field instead")
    fail(f"{name}: a search must be a mapping or a list of mappings")


def _compile_selection(
    name: str, selection: Mapping[Any, Any], fail: Callable[[str], NoReturn]
) -> Matcher:
    if not selection:
        fail(f"{name}: a selection needs at least one field")
    return _all_of(
        [_compile_field(name, str(key), value, fail) for key, value in selection.items()]
    )


def _compile_field(name: str, spec: str, value: Any, fail: Callable[[str], NoReturn]) -> Matcher:
    field_name, *modifiers = spec.split("|")
    where = f"{name}: {spec}"

    if not field_name:
        fail(f"{where}: keyword searches are not supported; name the field")
    unknown = [m for m in modifiers if m not in _MODIFIERS]
    if unknown:
        fail(f"{where}: unsupported modifier {unknown[0]!r}")
    mods = set(modifiers)
    if len(mods) != len(modifiers):
        fail(f"{where}: a modifier is repeated")

    if "exists" in mods:
        if mods != {"exists"} or not isinstance(value, bool):
            fail(f"{where}: exists takes true or false and no other modifier")
        return lambda event: (_lookup(event, field_name) is not None) is value

    if len(mods & _POSITION_MODIFIERS) > 1:
        fail(f"{where}: contains, startswith and endswith are mutually exclusive")
    flags = mods & set(_REGEX_FLAGS)
    if "re" in mods:
        clashing = mods & (_POSITION_MODIFIERS | {"cased"})
        if clashing:
            fail(f"{where}: re cannot be combined with {', '.join(sorted(clashing))}")
    elif flags:
        fail(f"{where}: the {', '.join(sorted(flags))} flags apply only to re")

    values = value if isinstance(value, list) else [value]
    if not values:
        fail(f"{where}: no values given")

    if any(v is None for v in values):
        if len(values) > 1 or mods:
            fail(f"{where}: null stands alone, without modifiers or other values")
        return lambda event: _lookup(event, field_name) in (None, "")

    # Every value, wildcard or regular expression, compiles to a pattern that
    # must cover the whole field.
    patterns = [_compile_value(v, mods, where, fail) for v in values]
    require_all = "all" in mods

    def match(event: Event) -> bool:
        actual = _lookup(event, field_name)
        if actual is None:
            return False
        items = actual if isinstance(actual, (list, tuple)) else (actual,)
        texts = [_text(item) for item in items if item is not None]

        def hit(pattern: re.Pattern[str]) -> bool:
            return any(pattern.fullmatch(t) for t in texts)

        if require_all:
            return all(hit(p) for p in patterns)
        return any(hit(p) for p in patterns)

    return match


def _compile_value(
    value: Any, mods: set[str], where: str, fail: Callable[[str], NoReturn]
) -> re.Pattern[str]:
    if isinstance(value, (Mapping, list)):
        fail(f"{where}: values must be scalars")

    if "re" in mods:
        if not isinstance(value, str):
            fail(f"{where}: a regular expression must be a string")
        # Lucene's "." matches any character, newlines included.
        flags = re.DOTALL
        for flag in mods & set(_REGEX_FLAGS):
            flags |= _REGEX_FLAGS[flag]
        try:
            return re.compile(value, flags)
        except re.error as exc:
            fail(f"{where}: invalid regular expression {value!r}: {exc}")

    text = _text(value)
    if "contains" in mods:
        text = f"*{text}*"
    elif "startswith" in mods:
        text = f"{text}*"
    elif "endswith" in mods:
        text = f"*{text}"
    return _wildcard(text, cased="cased" in mods)


def _wildcard(value: str, *, cased: bool) -> re.Pattern[str]:
    """Translate a Sigma string into a regular expression.

    ``*`` and ``?`` are wildcards. A backslash escapes a following ``*``, ``?``
    or backslash; before anything else it is an ordinary character, so
    ``\\x7f`` in a rule means a literal backslash followed by ``x7f``.
    """
    parts: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 1 < len(value) and value[index + 1] in "*?\\":
            parts.append(re.escape(value[index + 1]))
            index += 2
            continue
        if char == "*":
            parts.append(".*")
        elif char == "?":
            parts.append(".")
        else:
            parts.append(re.escape(char))
        index += 1
    flags = re.DOTALL | (0 if cased else re.IGNORECASE)
    return re.compile("".join(parts), flags)


def _text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _lookup(event: Event, field_name: str) -> Any:
    """Read a field by its flat name, or by walking a dotted path."""
    if field_name in event:
        return event[field_name]
    current: Any = event
    for part in field_name.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return None
        current = current[part]
    return current


def _compile_condition(
    text: str,
    searches: Mapping[str, Matcher],
    used: set[str],
    fail: Callable[[str], NoReturn],
) -> Matcher:
    """Parse a condition with the precedence Sigma defines: not, then and, then or."""
    if "|" in text:
        fail("aggregations in conditions (|) are not supported")

    tokens = _CONDITION_TOKEN.findall(text)
    position = 0

    def peek() -> str | None:
        return tokens[position] if position < len(tokens) else None

    def take() -> str:
        nonlocal position
        if position >= len(tokens):
            fail(f"condition {text!r} ends unexpectedly")
        token = tokens[position]
        position += 1
        return token

    def expression() -> Matcher:
        operands = [conjunction()]
        while peek() == "or":
            take()
            operands.append(conjunction())
        return operands[0] if len(operands) == 1 else _any_of(operands)

    def conjunction() -> Matcher:
        operands = [negation()]
        while peek() == "and":
            take()
            operands.append(negation())
        return operands[0] if len(operands) == 1 else _all_of(operands)

    def negation() -> Matcher:
        if peek() == "not":
            take()
            return _negate(negation())
        return primary()

    def primary() -> Matcher:
        token = take()
        if token == "(":
            inner = expression()
            if take() != ")":
                fail(f"condition {text!r} has an unbalanced parenthesis")
            return inner

        if token in ("1", "all"):
            if take() != "of":
                fail(f"expected 'of' after {token!r} in condition {text!r}")
            target = take()
            if target == "them":
                # Identifiers starting with an underscore are helpers that must
                # be referenced by name; "them" deliberately leaves them out.
                names = [n for n in searches if not n.startswith("_")]
            else:
                names = [n for n in searches if fnmatch.fnmatchcase(n, target)]
            if not names:
                fail(f"'{token} of {target}' matches no search identifier")
            used.update(names)
            members = [searches[n] for n in names]
            return _any_of(members) if token == "1" else _all_of(members)

        if token in ("and", "or", "not", "of", "them", ")"):
            fail(f"unexpected {token!r} in condition {text!r}")
        if token not in searches:
            fail(f"condition refers to undefined search identifier {token!r}")
        used.add(token)
        return searches[token]

    matcher = expression()
    if position != len(tokens):
        fail(f"unexpected {tokens[position]!r} in condition {text!r}")
    return matcher
