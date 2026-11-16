"""Shared fixtures and the no-skip guard.

Locally, tests that need liboqs skip when it isn't built, and ``go``-marked
tests skip without ``QTLS_GO_DEMO``. In CI ``QTLS_NO_SKIPS=1`` makes any skip
fail the run, so the crypto can never be silently bypassed (docs/PLAN.md,
Phase 1), and ``QTLS_MIN_OPENSSL_TESTS`` / ``QTLS_MIN_GO_TESTS`` fail it when
fewer marked tests passed than CI expects (a deselected or uncollected suite).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from qtls import crypto


def _liboqs_available() -> str | None:
    try:
        crypto._oqs()
    except crypto.BackendUnavailable as exc:
        return str(exc)
    return None


@pytest.fixture(scope="session")
def require_liboqs() -> None:
    reason = _liboqs_available()
    if reason is not None:
        pytest.skip(f"liboqs unavailable: {reason}")


@pytest.fixture(scope="session")
def require_openssl() -> str:
    """The OpenSSL binary for ``openssl``-marked tests (tests/openssl_tools.py)."""
    from openssl_tools import locate  # here, so a conftest copied elsewhere still imports

    binary, why = locate()
    if binary is None:
        pytest.skip(why)
    return binary


@pytest.fixture(scope="session")
def go_demo() -> Path:
    """The pinned WG Go demo for ``go``-marked tests (scripts/mtc_demo.py --build-only; specs.md D34)."""
    path = os.environ.get("QTLS_GO_DEMO")
    if not path:
        pytest.skip("QTLS_GO_DEMO isn't set (build the demo with scripts/mtc_demo.py --build-only)")
    binary = Path(path)
    if not (binary.is_file() and os.access(binary, os.X_OK)):
        pytest.fail(f"QTLS_GO_DEMO={path} isn't an executable")
    return binary


@pytest.fixture(params=crypto.BACKENDS)
def backend(request: pytest.FixtureRequest) -> str:
    if request.param == "liboqs":
        request.getfixturevalue("require_liboqs")
    return request.param


pytest_plugins = ["pytester"]


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Mark every test that needs liboqs, so ``-m "not liboqs"`` works."""
    for item in items:
        for marker in _GATES:
            if item.get_closest_marker(marker) is not None:  # the mark, not a "[openssl]" parameter id
                _gated_nodeids[marker].add(item.nodeid)
        params = getattr(getattr(item, "callspec", None), "params", {})
        if (
            "require_liboqs" in getattr(item, "fixturenames", ())
            or "liboqs" in (params.get("backend"), params.get("backend_name"))
        ):
            item.add_marker(pytest.mark.liboqs)


# Marked suites CI requires to have run: marker -> the variable holding how many must pass.
_GATES = {"openssl": "QTLS_MIN_OPENSSL_TESTS", "go": "QTLS_MIN_GO_TESTS"}
_gated_passed = dict.fromkeys(_GATES, 0)
_gated_nodeids: dict[str, set[str]] = {marker: set() for marker in _GATES}


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    if report.when == "call" and report.passed:
        for marker, nodeids in _gated_nodeids.items():
            if report.nodeid in nodeids:
                _gated_passed[marker] += 1


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if os.environ.get("QTLS_NO_SKIPS") != "1":
        return
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    # Skips are caught below; this catches a deselected or uncollected marked suite.
    for marker, variable in _GATES.items():
        minimum = int(os.environ.get(variable, "0"))
        if _gated_passed[marker] < minimum:
            if reporter:
                reporter.write_line(f"only {_gated_passed[marker]} {marker} test(s) passed; CI needs {minimum}.", red=True)
            session.exitstatus = pytest.ExitCode.TESTS_FAILED
    stats = reporter.stats if reporter else {}
    skipped = len(stats.get("skipped", [])) + len(stats.get("xfailed", []))
    if skipped:
        if reporter:
            reporter.write_line(
                f"QTLS_NO_SKIPS=1: {skipped} test(s) skipped or xfailed; failing the run.",
                red=True,
            )
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
