"""Keep docs/threat-model.md §5 and docs/specs.md §4 honest.

* Every property row (``| Pn | ... |``) parses, IDs are sequential, and the set
  never shrinks below MIN_PROPERTIES.
* Every decision (``### Dn.``) has Ambiguity, Decision, Rejected reading and
  Tests fields, and IDs are sequential.
* A status is ``implemented`` or ``planned: Phase N`` (``Phases N and M`` /
  ``N–M``), and every planned phase must be later than the last phase PLAN.md
  records as met.
* An implemented property cites only well-formed references to collected,
  module-level ``test_*`` functions in ``tests/test_*.py``, each defined once.

The checker functions return a list of problems so the self-tests at the bottom
can feed them mutated documents.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
THREAT_MODEL = ROOT / "docs" / "threat-model.md"
SPECS = ROOT / "docs" / "specs.md"
PLAN = ROOT / "docs" / "PLAN.md"

MIN_PROPERTIES = 15
MIN_DECISIONS = 19

PROPERTY_LINE = re.compile(r"^\|\s*P\d", re.M)
PROPERTY_ROW = re.compile(r"^\| (P\d+) \| ([^|]+) \| ([^|]+) \| ([^|]+) \| ([^|]+) \| ([^|]+) \|$")
STATUS = re.compile(r"^(implemented|planned: Phases? (\d+)((?:(?:–| and |, )\d+)*))$")
REF = re.compile(r"^tests/(test_\w+)\.py::(test_\w+)$")
DECISION_HEADER = re.compile(r"^### (D\d+)\. \S", re.M)
DECISION_FIELDS = ("Ambiguity", "Decision", "Rejected reading", "Tests")


def met_phases(plan_text: str) -> set[int]:
    """Phases whose PLAN.md section records '**Met on'."""
    met = set()
    sections = re.split(r"^### Phase (\d+):", plan_text, flags=re.M)
    for number, body in zip(sections[1::2], sections[2::2], strict=True):
        if "**Met on" in body:
            met.add(int(number))
    return met


def check_status(where: str, status: str, met: set[int]) -> list[str]:
    m = STATUS.fullmatch(status)
    if not m:
        return [f"{where}: malformed status {status!r}"]
    if m.group(1) == "implemented":
        return []
    phases = [int(p) for p in re.findall(r"\d+", status)]
    last_met = max(met, default=-1)
    stale = [p for p in phases if p <= last_met]
    if stale:
        return [f"{where}: planned for phase(s) {stale}, but phase {last_met} is already met"]
    return []


def collected_tests(root: Path) -> dict[tuple[str, str], int]:
    """(module, function) -> count of module-level test_* definitions."""
    found: dict[tuple[str, str], int] = {}
    for path in sorted((root / "tests").glob("test_*.py")):
        tree = ast.parse(path.read_text())
        for node in tree.body:  # module level only: nested defs and methods don't count
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name.startswith(
                "test_"
            ):
                key = (path.stem, node.name)
                found[key] = found.get(key, 0) + 1
    return found


def check_refs(where: str, cell: str, tests: dict[tuple[str, str], int]) -> list[str]:
    problems = []
    tokens = re.findall(r"`([^`]*)`", cell)
    leftover = re.sub(r"`[^`]*`", "", cell)
    if leftover.replace(",", "").strip():
        problems.append(f"{where}: text outside citations: {leftover.strip()!r}")
    if not tokens:
        problems.append(f"{where}: implemented but cites no tests")
    for token in tokens:
        m = REF.fullmatch(token)
        if not m:
            problems.append(f"{where}: malformed test reference {token!r}")
            continue
        count = tests.get((m.group(1), m.group(2)), 0)
        if count == 0:
            problems.append(f"{where}: {token} is not a collected module-level test")
        elif count > 1:
            problems.append(f"{where}: {token} is defined {count} times (later ones shadow it)")
    return problems


def check_threat_model(text: str, plan_text: str, root: Path) -> list[str]:
    problems = []
    met = met_phases(plan_text)
    tests = collected_tests(root)
    ids = []
    for line in text.splitlines():
        if not PROPERTY_LINE.match(line):
            continue
        row = PROPERTY_ROW.fullmatch(line)
        if not row:
            problems.append(f"unparseable property row: {line[:60]!r}")
            continue
        pid, _prop, _against, _configs, status, cell = (c.strip() for c in row.groups())
        ids.append(pid)
        problems += check_status(pid, status, met)
        if status == "implemented":
            problems += check_refs(pid, cell, tests)
    if ids != [f"P{i}" for i in range(1, len(ids) + 1)]:
        problems.append(f"property IDs not sequential and unique: {ids}")
    if len(ids) < MIN_PROPERTIES:
        problems.append(f"only {len(ids)} properties; expected at least {MIN_PROPERTIES}")
    return problems


def check_specs(text: str, plan_text: str, root: Path) -> list[str]:
    problems = []
    met = met_phases(plan_text)
    tests = collected_tests(root)
    headers = list(DECISION_HEADER.finditer(text))
    ids = [h.group(1) for h in headers]
    ends = [h.start() for h in headers[1:]] + [text.find("\n## ", headers[-1].end()) if headers else 0]
    for header, end in zip(headers, ends, strict=True):
        did = header.group(1)
        body = text[header.end() : end if end > 0 else len(text)]
        for field in DECISION_FIELDS:
            # Content on the same line, or an indented sub-list on the next line.
            if not re.search(rf"^- \*\*{field}:\*\*( \S|\n  - \S)", body, re.M):
                problems.append(f"{did}: missing '{field}' field")
        tests_line = re.search(r"^- \*\*Tests:\*\* (.+)$", body, re.M)
        if tests_line:
            status, _, rest = tests_line.group(1).partition(" — ")
            problems += check_status(did, status.strip(), met)
            if status.strip() == "implemented":
                problems += check_refs(did, rest, tests)
            elif not rest.strip():
                problems.append(f"{did}: planned test has no description")
    if ids != [f"D{i}" for i in range(1, len(ids) + 1)]:
        problems.append(f"decision IDs not sequential and unique: {ids}")
    if len(ids) < MIN_DECISIONS:
        problems.append(f"only {len(ids)} decisions; expected at least {MIN_DECISIONS}")
    return problems


# --------------------------------------------------------------------------- #
# The real documents
# --------------------------------------------------------------------------- #


def test_threat_model_is_traceable() -> None:
    assert check_threat_model(THREAT_MODEL.read_text(), PLAN.read_text(), ROOT) == []


def test_specs_decisions_are_traceable() -> None:
    assert check_specs(SPECS.read_text(), PLAN.read_text(), ROOT) == []


def test_plan_records_phases_0_and_1_as_met() -> None:
    assert {0, 1} <= met_phases(PLAN.read_text())


# --------------------------------------------------------------------------- #
# Self-tests: each mutation the Phase 0 review found must be caught.
# --------------------------------------------------------------------------- #

GOOD_REF = "`tests/test_crypto.py::test_unknown_names_raise`"


def _mutate(old: str, new: str, *, text: str | None = None) -> list[str]:
    text = text if text is not None else THREAT_MODEL.read_text()
    assert old in text, old
    return check_threat_model(text.replace(old, new, 1), PLAN.read_text(), ROOT)


THREAT_MODEL_MUTANTS = {
    "renamed test": (GOOD_REF, "`tests/test_crypto.py::test_unknown_names_raiseX`"),
    "nested function": (GOOD_REF, "`tests/test_crypto.py::role`"),
    "helper function": (GOOD_REF, "`tests/test_crypto.py::_corruptions`"),
    "conftest helper": (GOOD_REF, "`tests/conftest.py::_liboqs_available`"),
    "wrong file": (GOOD_REF, "`tests/test_kat.py::test_unknown_names_raise`"),
    "parametrized id": (GOOD_REF, "`tests/test_crypto.py::test_unknown_names_raise[x]`"),
    "single colon": (GOOD_REF, "`tests/test_crypto.py:test_unknown_names_raise`"),
    "hyphenated file": (GOOD_REF, "`tests/test-crypto.py::test_unknown_names_raise`"),
    "unbackticked ref": (GOOD_REF, "tests/test_crypto.py::test_unknown_names_raise"),
    "status letters": ("| planned: Phase 5 |", "| planned: Phase and |"),
    "status already met": ("| planned: Phase 5 |", "| planned: Phase 1 |"),
    "status typo": ("| implemented | `tests/test_crypto.py::test_every", "| implemneted | `tests/test_crypto.py::test_every"),
    "malformed row prefix": ("| P15 |", "|P15 |"),
    "duplicate id": ("| P14 |", "| P13 |"),
}


@pytest.mark.parametrize("mutant", THREAT_MODEL_MUTANTS, ids=list(THREAT_MODEL_MUTANTS))
def test_threat_model_checker_catches(mutant: str) -> None:
    old, new = THREAT_MODEL_MUTANTS[mutant]
    assert _mutate(old, new) != []


def test_checker_catches_deleted_rows() -> None:
    text = THREAT_MODEL.read_text()
    kept = "\n".join(line for line in text.splitlines() if not line.startswith("| P15 |"))
    assert check_threat_model(kept, PLAN.read_text(), ROOT) != []


def test_checker_catches_shadowed_tests(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("def test_a():\n    assert 0\n\ndef test_a():\n    pass\n")
    assert check_refs("P0", "`tests/test_x.py::test_a`", collected_tests(tmp_path)) != []


def test_checker_catches_methods_and_uncollected_dirs(tmp_path: Path) -> None:
    (tmp_path / "tests" / "vectors").mkdir(parents=True)
    (tmp_path / "tests" / "test_x.py").write_text("class Helper:\n    def test_m(self):\n        pass\n")
    (tmp_path / "tests" / "vectors" / "test_y.py").write_text("def test_y():\n    pass\n")
    tests = collected_tests(tmp_path)
    assert check_refs("P0", "`tests/test_x.py::test_m`", tests) != []
    assert check_refs("P0", "`tests/vectors/test_y.py::test_y`", tests) != []


SPECS_MUTANTS = {
    "missing rejected reading": ("- **Rejected reading:** an empty IKM.", ""),
    "missing tests field": ("- **Tests:** planned: Phase 3 — an SPKI-hash vector", "- Tests: planned: Phase 3 — an SPKI-hash vector"),
    "bad status": ("- **Tests:** planned: Phase 4 — a finished_key vector", "- **Tests:** planned: Phase four — a finished_key vector"),
    "met phase": ("- **Tests:** planned: Phase 4 — a finished_key vector", "- **Tests:** planned: Phase 0 — a finished_key vector"),
    "no description": ("- **Tests:** planned: Phase 4 — a finished_key vector; a mutant using the doubled prefix fails it.", "- **Tests:** planned: Phase 4"),
    "duplicate id": ("### D18.", "### D17."),
}


@pytest.mark.parametrize("mutant", SPECS_MUTANTS, ids=list(SPECS_MUTANTS))
def test_specs_checker_catches(mutant: str) -> None:
    old, new = SPECS_MUTANTS[mutant]
    text = SPECS.read_text()
    assert old in text, old
    assert check_specs(text.replace(old, new, 1), PLAN.read_text(), ROOT) != []
