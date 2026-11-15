"""The environment is the pinned one: exact library versions, and a clean repo."""

from __future__ import annotations

import hashlib
import importlib.metadata
import os
import re
import shutil
import subprocess
import sys
import tomllib
import warnings
from pathlib import Path

import pytest

from qtls import crypto

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text())


def _pin(requirement_list: list[str], package: str) -> str:
    for req in requirement_list:
        m = re.fullmatch(rf"{re.escape(package)}==([\w.]+)", req)
        if m:
            return m.group(1)
    raise AssertionError(f"{package} is not pinned with == in pyproject.toml")


def test_cryptography_matches_pin() -> None:
    expected = _pin(PYPROJECT["project"]["dependencies"], "cryptography")
    assert importlib.metadata.version("cryptography") == expected


@pytest.mark.usefixtures("require_liboqs")
def test_liboqs_python_matches_pin() -> None:
    expected = _pin(PYPROJECT["project"]["optional-dependencies"]["oqs"], "liboqs-python")
    assert importlib.metadata.version("liboqs-python") == expected


@pytest.mark.usefixtures("require_liboqs")
def test_native_liboqs_is_the_pinned_build() -> None:
    oqs = crypto._oqs()
    assert oqs.oqs_version() == crypto.LIBOQS_VERSION
    script = (ROOT / "scripts" / "build_liboqs.sh").read_text()
    assert f'LIBOQS_TAG="{crypto.LIBOQS_VERSION}"' in script
    assert f'LIBOQS_SHA="{crypto.LIBOQS_SHA}"' in script


def test_openssl_build_script_matches_the_pin() -> None:
    import openssl_tools

    script = (ROOT / "scripts" / "build_openssl.sh").read_text()
    assert f'OPENSSL_TAG="{openssl_tools.OPENSSL_TAG}"' in script
    assert f'OPENSSL_SHA="{openssl_tools.OPENSSL_SHA}"' in script


def test_ci_refuses_an_unpinned_openssl(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """With QTLS_NO_SKIPS=1 there is no PATH fallback, and the binary must be the recorded pinned build."""
    import openssl_tools

    monkeypatch.setenv("QTLS_NO_SKIPS", "1")
    monkeypatch.delenv("QTLS_OPENSSL", raising=False)
    assert openssl_tools.locate()[0] is None
    fake = tmp_path / "bin" / "openssl"
    fake.parent.mkdir()
    monkeypatch.setenv("QTLS_OPENSSL", str(fake))

    def build(version: str, *, tag: str = openssl_tools.OPENSSL_TAG, sha: str = openssl_tools.OPENSSL_SHA,
              recorded: str | None = None) -> tuple[str | None, str]:  # fmt: skip
        fake.write_text(f"#!/bin/sh\necho 'OpenSSL {version} 9 Jun 2026'\n")
        fake.chmod(0o755)
        digest = recorded or hashlib.sha256(fake.read_bytes()).hexdigest()
        (tmp_path / "BUILD_INFO").write_text(f"tag={tag}\nsha={sha}\nbin_sha256={digest}\n")
        return openssl_tools.locate()

    assert build("3.6.3") == (str(fake), "")
    refused = (None, f"{fake} isn't the pinned {openssl_tools.OPENSSL_TAG} build")
    assert build("3.6.3", recorded="0" * 64) == refused  # not the binary BUILD_INFO recorded
    assert build("3.6.2") == refused  # recorded, but another version
    assert build("3.6.3", sha="deadbeef") == refused
    assert build("3.6.3", tag="openssl-3.6.2") == refused


def test_liboqs_refused_without_pinned_build(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Never let liboqs-python's import-time downloader run."""
    monkeypatch.setattr(crypto, "_oqs_module", None)
    monkeypatch.delenv("OQS_INSTALL_PATH", raising=False)
    with pytest.raises(crypto.BackendUnavailable, match="OQS_INSTALL_PATH"):
        crypto.kem_generate("ML-KEM-512", "liboqs")
    monkeypatch.setenv("OQS_INSTALL_PATH", str(tmp_path))
    with pytest.raises(crypto.BackendUnavailable, match="BUILD_INFO"):
        crypto.kem_generate("ML-KEM-512", "liboqs")
    (tmp_path / "BUILD_INFO").write_text("tag=0.15.0\nsha=deadbeef\n")
    with pytest.raises(crypto.BackendUnavailable, match="BUILD_INFO"):
        crypto.kem_generate("ML-KEM-512", "liboqs")


def test_build_artifacts_are_not_tracked() -> None:
    tracked = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.splitlines()
    offenders = [p for p in tracked if p.split("/", 1)[0] in {"obj", "bin", ".oqs", ".openssl", ".venv"}]
    assert offenders == []


def test_pytest_never_collects_legacy() -> None:
    assert PYPROJECT["tool"]["pytest"]["ini_options"]["testpaths"] == ["tests"]


# --------------------------------------------------------------------------- #
# Added after the Phase 1 fleet review.
# --------------------------------------------------------------------------- #

def _script_value(name: str) -> str:
    script = (ROOT / "scripts" / "build_liboqs.sh").read_text()
    m = re.search(rf'^{name}="([^"]+)"$', script, re.M)
    assert m, name
    return m.group(1)


def _script_flags() -> str:
    script = (ROOT / "scripts" / "build_liboqs.sh").read_text()
    m = re.search(r"^CMAKE_FLAGS=\(\n(.*?)^\)", script, re.M | re.S)
    assert m
    return " ".join(line.strip() for line in m.group(1).splitlines() if line.strip().startswith("-D"))


def test_build_script_and_wrapper_agree() -> None:
    assert _script_value("LIBOQS_TAG") == crypto.LIBOQS_VERSION
    assert _script_value("LIBOQS_SHA") == crypto.LIBOQS_SHA
    assert _script_flags() == crypto.LIBOQS_CMAKE_FLAGS
    assert "-DOQS_USE_OPENSSL=OFF" in crypto.LIBOQS_CMAKE_FLAGS


def _good_header() -> str:
    return (
        f"tag={crypto.LIBOQS_VERSION}\nsha={crypto.LIBOQS_SHA}\n"
        f"cmake_flags={crypto.LIBOQS_CMAKE_FLAGS}\n"
    )


def _run_isolated(install: Path, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    """Call the liboqs backend in a fresh interpreter with a booby-trapped git."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    marker = tmp_path / "git-was-called"
    stub = bin_dir / "git"
    stub.write_text(f"#!/bin/sh\ntouch {marker}\nexit 1\n")
    stub.chmod(0o755)
    code = (
        "import sys\n"
        "from qtls import crypto\n"
        "try:\n"
        "    crypto.kem_generate('ML-KEM-512', 'liboqs')\n"
        "except crypto.BackendUnavailable as e:\n"
        "    print('UNAVAILABLE', e)\n"
        "print('OQS_IMPORTED' if 'oqs' in sys.modules else 'OQS_NOT_IMPORTED')\n"
    )
    env = {**os.environ, "OQS_INSTALL_PATH": str(install), "PATH": f"{bin_dir}:{os.environ['PATH']}"}
    env.pop("DYLD_LIBRARY_PATH", None)
    env.pop("LD_LIBRARY_PATH", None)
    result = subprocess.run(
        [sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=60
    )
    assert not marker.exists(), "liboqs-python's auto-installer ran (git was invoked)"
    return result


def test_build_info_without_library_never_reaches_the_installer(tmp_path: Path) -> None:
    install = tmp_path / "oqs"
    install.mkdir()
    (install / "BUILD_INFO").write_text(_good_header() + "lib=lib/liboqs.so\nlib_sha256=00\n")
    result = _run_isolated(install, tmp_path)
    assert "UNAVAILABLE" in result.stdout and "missing" in result.stdout, result
    assert "OQS_NOT_IMPORTED" in result.stdout, result


@pytest.mark.parametrize(
    "header",
    [
        "tag=0.16.0\nsha=5a1a854b0dc9f2141bdc771c555ee60c37950183\ncmake_flags=-DOQS_USE_OPENSSL=ON\n",
        "tag=0.15.0\nsha=deadbeef\ncmake_flags=x\n",
        "",
    ],
    ids=["other-flags", "other-version", "empty"],
)
def test_mismatched_build_info_is_refused_before_import(tmp_path: Path, header: str) -> None:
    install = tmp_path / "oqs"
    install.mkdir()
    (install / "BUILD_INFO").write_text(header)
    result = _run_isolated(install, tmp_path)
    assert "UNAVAILABLE" in result.stdout and "BUILD_INFO" in result.stdout, result
    assert "OQS_NOT_IMPORTED" in result.stdout, result


@pytest.mark.usefixtures("require_liboqs")
def test_tampered_library_is_refused(tmp_path: Path) -> None:
    real = Path(os.environ["OQS_INSTALL_PATH"])
    install = tmp_path / "oqs"
    shutil.copytree(real, install, symlinks=True)
    info = crypto._read_build_info(install)
    lib = install / info["lib"]
    data = bytearray(lib.read_bytes())
    data[-1] ^= 0x01
    lib.write_bytes(bytes(data))
    result = _run_isolated(install, tmp_path)
    assert "UNAVAILABLE" in result.stdout and "SHA-256" in result.stdout, result
    assert "OQS_NOT_IMPORTED" in result.stdout, result


@pytest.mark.usefixtures("require_liboqs")
@pytest.mark.parametrize(
    ("name", "version", "message"),
    [
        ("liboqs.9.dylib", crypto.LIBOQS_VERSION, "bare name"),
        ("/opt/elsewhere/lib/liboqs.so", crypto.LIBOQS_VERSION, "not the pinned build"),
        (None, "0.15.0", "version"),
    ],
    ids=["bare-name", "other-path", "other-version"],
)
def test_loaded_library_is_verified(
    monkeypatch: pytest.MonkeyPatch, name: str | None, version: str, message: str
) -> None:
    oqs = crypto._oqs()
    real_name = oqs.native()._name

    class FakeLib:
        _name = name or real_name

    monkeypatch.setattr(crypto, "_oqs_module", None)
    monkeypatch.setattr(oqs, "native", lambda: FakeLib())
    monkeypatch.setattr(oqs, "oqs_version", lambda: version)
    with pytest.raises(crypto.BackendUnavailable, match=message):
        crypto._oqs()


@pytest.mark.usefixtures("require_liboqs")
def test_liboqs_links_no_external_libcrypto() -> None:
    install = Path(os.environ["OQS_INSTALL_PATH"])
    lib = install / crypto._read_build_info(install)["lib"]
    assert b"libcrypto" not in lib.read_bytes()


def test_warnings_are_errors() -> None:
    with pytest.raises(UserWarning):
        warnings.warn("must fail the test run", UserWarning, stacklevel=1)


@pytest.mark.parametrize(
    ("body", "no_skips", "expected"),
    [
        ("import pytest\ndef test_s():\n    pytest.skip('x')\n", "1", 1),
        ("import pytest\ndef test_s():\n    pytest.skip('x')\n", "0", 0),
        ("import pytest\n@pytest.mark.xfail\ndef test_x():\n    assert 0\n", "1", 1),
        ("def test_ok():\n    pass\n", "1", 0),
    ],
    ids=["skip-guarded", "skip-unguarded", "xfail-guarded", "pass-guarded"],
)
def test_no_skip_guard(
    pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch, body: str, no_skips: str, expected: int
) -> None:
    pytester.makeconftest((ROOT / "tests" / "conftest.py").read_text().replace(
        'pytest_plugins = ["pytester"]', ""
    ))
    pytester.makepyfile(body)
    monkeypatch.setenv("QTLS_NO_SKIPS", no_skips)
    monkeypatch.delenv("QTLS_MIN_OPENSSL_TESTS", raising=False)  # set in CI; this run has no OpenSSL tests
    assert pytester.runpytest_subprocess("-p", "no:cacheprovider").ret == expected


@pytest.mark.parametrize(("args", "expected"), [((), 0), (("-m", "not openssl"), 1), (("-k", "not test_b"), 1)],
                         ids=["ran", "deselected", "one-deselected"])  # fmt: skip
def test_ci_needs_the_openssl_tests_to_have_run(
    pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch, args: tuple[str, ...], expected: int
) -> None:
    """QTLS_NO_SKIPS catches skips; QTLS_MIN_OPENSSL_TESTS catches a deselected or uncollected suite."""
    pytester.makeconftest((ROOT / "tests" / "conftest.py").read_text().replace('pytest_plugins = ["pytester"]', ""))
    pytester.makeini("[pytest]\nmarkers =\n    openssl: x\n")
    pytester.makepyfile(
        "import pytest\n@pytest.mark.openssl\ndef test_a():\n    pass\n@pytest.mark.openssl\ndef test_b():\n    pass\n"
        # Parametrize ids named "openssl" are keywords too; they mustn't count (full-review Block).
        "@pytest.mark.parametrize('backend', ['openssl', 'liboqs'])\ndef test_c(backend):\n    pass\n"
    )
    monkeypatch.setenv("QTLS_NO_SKIPS", "1")
    monkeypatch.setenv("QTLS_MIN_OPENSSL_TESTS", "2")
    assert pytester.runpytest_subprocess("-p", "no:cacheprovider", *args).ret == expected


def test_only_crypto_module_imports_crypto_libraries() -> None:
    pattern = re.compile(r"^\s*(import|from)\s+(oqs|cryptography)\b", re.M)
    offenders = [
        str(p.relative_to(ROOT))
        for p in (ROOT / "qtls").rglob("*.py")
        if p.name != "crypto.py" and pattern.search(p.read_text())
    ]
    assert offenders == []


def test_vendored_vectors_match_recorded_hashes() -> None:
    """Every file under tests/vectors is pinned by SHA-256 in its directory's SOURCE."""
    vectors = ROOT / "tests" / "vectors"
    dirs = sorted(d for d in vectors.iterdir() if d.is_dir())
    assert {d.name for d in dirs} >= {"acvp", "liboqs", "rfc7748", "rfc8448"}
    for d in dirs:
        source = d / "SOURCE"
        assert source.is_file(), f"{d.name} has no SOURCE file"
        recorded = dict(re.findall(r"^sha256 (\S+): ([0-9a-f]{64})$", source.read_text(), re.M))
        present = {str(p.relative_to(d)) for p in d.rglob("*") if p.is_file() and p.name != "SOURCE"}
        assert set(recorded) == present, f"{d.name}: unpinned or missing files"
        for name, digest in recorded.items():
            assert hashlib.sha256((d / name).read_bytes()).hexdigest() == digest, f"{d.name}/{name}"


def test_ci_openssl_floor_equals_the_collected_openssl_tests() -> None:
    """Adding an OpenSSL test must raise CI's floor too, or deselecting it would go unnoticed."""
    floor = re.search(r'QTLS_MIN_OPENSSL_TESTS: "(\d+)"', (ROOT / ".github" / "workflows" / "ci.yml").read_text())
    assert floor is not None
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-m", "openssl", "-p", "no:cacheprovider", "tests"],
        cwd=ROOT, capture_output=True, text=True, check=True,
        env={k: v for k, v in os.environ.items() if k not in ("QTLS_NO_SKIPS", "QTLS_MIN_OPENSSL_TESTS")},  # collection only
    )  # fmt: skip
    collected = [line for line in result.stdout.splitlines() if "::" in line]
    assert int(floor[1]) == len(collected)
