"""Shared fixtures and the no-skip guard.

Locally, tests that need liboqs skip when it isn't built. In CI
``QTLS_NO_SKIPS=1`` makes any skip fail the run, so the crypto can never be
silently bypassed (docs/PLAN.md, Phase 1).
"""

from __future__ import annotations

import os

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


@pytest.fixture(params=crypto.BACKENDS)
def backend(request: pytest.FixtureRequest) -> str:
    if request.param == "liboqs":
        request.getfixturevalue("require_liboqs")
    return request.param


pytest_plugins = ["pytester"]


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Mark every test that needs liboqs, so ``-m "not liboqs"`` works."""
    for item in items:
        if item.get_closest_marker("openssl") is not None:  # the mark, not a "[openssl]" parameter id
            _openssl_nodeids.add(item.nodeid)
        params = getattr(getattr(item, "callspec", None), "params", {})
        if (
            "require_liboqs" in getattr(item, "fixturenames", ())
            or "liboqs" in (params.get("backend"), params.get("backend_name"))
        ):
            item.add_marker(pytest.mark.liboqs)


_openssl_passed = 0
_openssl_nodeids: set[str] = set()


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    global _openssl_passed
    if report.when == "call" and report.passed and report.nodeid in _openssl_nodeids:
        _openssl_passed += 1


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if os.environ.get("QTLS_NO_SKIPS") != "1":
        return
    # Skips are caught below; this catches a deselected or uncollected OpenSSL suite.
    minimum = int(os.environ.get("QTLS_MIN_OPENSSL_TESTS", "0"))
    if _openssl_passed < minimum:
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        if reporter:
            reporter.write_line(f"only {_openssl_passed} openssl test(s) passed; CI needs {minimum}.", red=True)
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    stats = reporter.stats if reporter else {}
    skipped = len(stats.get("skipped", [])) + len(stats.get("xfailed", []))
    if skipped:
        if reporter:
            reporter.write_line(
                f"QTLS_NO_SKIPS=1: {skipped} test(s) skipped or xfailed; failing the run.",
                red=True,
            )
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
