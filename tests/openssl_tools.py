"""The OpenSSL command-line tool as an independent TLS stack (not a test module).

Tests that use it carry the ``openssl`` marker and take the ``require_openssl``
fixture (tests/conftest.py). In CI (``QTLS_NO_SKIPS=1``) the binary must be
``$QTLS_OPENSSL`` from scripts/build_openssl.sh, at the pinned version; there
is no PATH fallback. Locally the pinned build in ``.openssl`` is preferred,
then any OpenSSL >= 3.5.

Process hygiene (from the 2e plan review): servers bind ``127.0.0.1:0`` and
report their port on the ``ACCEPT`` line; stdin is an open pipe (s_server
quits at stdin EOF); every wait has a timeout; every process is killed and
reaped on exit.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import os
import pty
import re
import selectors
import shutil
import socket
import subprocess
import termios
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509 as cx
from cryptography.hazmat.primitives import serialization

from qtls import chains, crypto

ROOT = Path(__file__).resolve().parent.parent
OPENSSL_TAG = "openssl-3.6.3"  # keep in sync with scripts/build_openssl.sh
OPENSSL_SHA = "aae016bfd52fcad2bc9657c2c782cfdf73b1ed5f"
MIN_VERSION = (3, 5)
KEYLOG_LABELS = (
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
    "EXPORTER_SECRET",
)
# What qTLS supports, pinned on the OpenSSL side so it can't negotiate anything else.
SUITE = "TLS_AES_128_GCM_SHA256"
GROUP = "X25519MLKEM768"


def _version(binary: str) -> tuple[int, int, int] | None:
    out = subprocess.run([binary, "version"], capture_output=True, text=True, timeout=10).stdout
    m = re.match(r"OpenSSL (\d+)\.(\d+)\.(\d+)", out)
    return (int(m[1]), int(m[2]), int(m[3])) if m else None


def pinned_version() -> tuple[int, int, int]:
    return tuple(int(x) for x in OPENSSL_TAG.removeprefix("openssl-").split("."))  # type: ignore[return-value]


def build_info(binary: str) -> dict[str, str]:
    info = Path(binary).resolve().parent.parent / "BUILD_INFO"
    if not info.is_file():
        return {}
    return dict(line.split("=", 1) for line in info.read_text().splitlines() if "=" in line)


def is_pinned_build(binary: str) -> bool:
    """BUILD_INFO next to the binary names the pinned tag and commit, and records this binary's SHA-256."""
    info = build_info(binary)
    if (info.get("tag"), info.get("sha")) != (OPENSSL_TAG, OPENSSL_SHA):
        return False
    if info.get("bin_sha256") != hashlib.sha256(Path(binary).read_bytes()).hexdigest():
        return False
    return _version(binary) == pinned_version()


def locate() -> tuple[str | None, str]:
    """(binary, why not) for the OpenSSL to test against."""
    if os.environ.get("QTLS_NO_SKIPS") == "1":
        binary = os.environ.get("QTLS_OPENSSL")
        if not binary or not Path(binary).is_file():
            return None, "QTLS_NO_SKIPS=1 needs QTLS_OPENSSL from scripts/build_openssl.sh"
        if not is_pinned_build(binary):
            return None, f"{binary} isn't the pinned {OPENSSL_TAG} build"
        return binary, ""
    candidates = [os.environ.get("QTLS_OPENSSL"), str(ROOT / ".openssl" / "bin" / "openssl"),
                  shutil.which("openssl"), "/opt/homebrew/opt/openssl@3/bin/openssl"]  # fmt: skip
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            version = _version(candidate)
            if version and version[:2] >= MIN_VERSION:
                return candidate, ""
    return None, "OpenSSL >= 3.5 not found (set QTLS_OPENSSL, or run scripts/build_openssl.sh)"


# --------------------------------------------------------------------------- #
# Files
# --------------------------------------------------------------------------- #


def pem(der: bytes) -> bytes:
    return cx.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM)


def private_key_pem(key: crypto.SigPrivateKey) -> bytes:
    """PKCS#8 for OpenSSL: from the key's own handle (openssl backend) or its seed."""
    if key.backend != "openssl":
        assert key.seed is not None, "a liboqs key needs its seed to move to OpenSSL"
        key = crypto.sig_generate(key.alg, "openssl", seed=key.seed)
    return key._handle.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption())  # fmt: skip


@dataclass(frozen=True)
class Pki:
    root: Path
    leaf: Path
    chain: Path  # the intermediates, for -cert_chain
    key: Path


def write_pki(directory: Path, chain: chains.Chain, key: crypto.SigPrivateKey) -> Pki:
    pki = Pki(directory / "root.pem", directory / "leaf.pem", directory / "chain.pem", directory / "key.pem")
    pki.root.write_bytes(pem(chain.root_der))
    pki.leaf.write_bytes(pem(chain.cert_data[0]))
    pki.chain.write_bytes(b"".join(pem(d) for d in chain.cert_data[1:]))
    pki.key.write_bytes(private_key_pem(key))
    return pki


def attime(now: dt.datetime) -> str:
    return str(int(now.timestamp()))


def keylog(path: Path, client_random: bytes) -> dict[str, str]:
    """OpenSSL's keylog lines for one connection (comments and other connections skipped)."""
    out: dict[str, str] = {}
    for line in path.read_text().splitlines():
        parts = line.split()
        if len(parts) == 3 and not line.startswith("#") and parts[1] == client_random.hex():
            assert parts[0] not in out, f"duplicate {parts[0]}"
            out[parts[0]] = parts[2]
    return out


def our_keylog(lines: list[str]) -> dict[str, str]:
    return {label: secret for label, _, secret in (line.split() for line in lines)}


# --------------------------------------------------------------------------- #
# Processes
# --------------------------------------------------------------------------- #


@dataclass
class Process:
    """An OpenSSL s_server or s_client with its output collected on a thread."""

    args: list[str]
    proc: subprocess.Popen[bytes] = field(init=False)
    _out: bytearray = field(default_factory=bytearray)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        # Output goes to a pseudo-terminal: OpenSSL block-buffers a pipe, which
        # would hold back the ACCEPT line (and everything else) until exit.
        self._master, slave = pty.openpty()
        try:
            attrs = termios.tcgetattr(slave)
            attrs[1] &= ~termios.OPOST  # no "\n" -> "\r\n", so received bytes come back as sent
            attrs[3] &= ~termios.ECHO
            termios.tcsetattr(slave, termios.TCSANOW, attrs)
            self.proc = subprocess.Popen(self.args, stdin=subprocess.PIPE, stdout=slave, stderr=slave)
        except BaseException:
            os.close(self._master)
            raise
        finally:
            os.close(slave)
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()

    def _read(self) -> None:
        while True:
            try:
                chunk = os.read(self._master, 65536)
            except OSError:  # EIO once the child has exited and closed the terminal
                break
            if not chunk:
                break
            with self._lock:
                self._out += chunk
        os.close(self._master)

    @property
    def output(self) -> bytes:
        with self._lock:
            return bytes(self._out)

    def text(self) -> str:
        return self.output.decode("latin-1")

    def wait_for(self, pattern: bytes, timeout: float = 15.0) -> re.Match[bytes]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            m = re.search(pattern, self.output)
            if m:
                return m
            if self.proc.poll() is not None:
                self._reader.join(timeout=1)
                m = re.search(pattern, self.output)
                if m:
                    return m
                raise AssertionError(f"{self.args[1]} exited ({self.proc.returncode}) without {pattern!r}:\n{self.text()}")
            time.sleep(0.01)
        raise TimeoutError(f"{self.args[1]} never printed {pattern!r}:\n{self.text()}")

    def write(self, data: bytes) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def finish(self, timeout: float = 15.0) -> str:
        """Close stdin, wait for exit (killing it on timeout), and return the output."""
        try:
            if self.proc.stdin and not self.proc.stdin.closed:
                self.proc.stdin.close()
        except BrokenPipeError:
            pass
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.kill()
        self._reader.join(timeout=5)
        return self.text()

    def kill(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait(timeout=10)

    def __enter__(self) -> Process:
        return self

    def __exit__(self, *exc: object) -> None:
        self.kill()
        for stream in (self.proc.stdin,):
            if stream and not stream.closed:
                try:
                    stream.close()
                except OSError:
                    pass
        self._reader.join(timeout=5)


def s_server(binary: str, pki: Pki, keylog_file: Path, *extra: str) -> tuple[Process, int]:
    """A one-connection s_server on 127.0.0.1 and its port."""
    proc = Process([binary, "s_server", "-accept", "127.0.0.1:0", "-naccept", "1", "-tls1_3",
                    "-ciphersuites", SUITE, "-cert", str(pki.leaf), "-cert_chain", str(pki.chain),
                    "-key", str(pki.key), "-keylogfile", str(keylog_file), *extra])  # fmt: skip
    try:
        port = int(proc.wait_for(rb"ACCEPT 127\.0\.0\.1:(\d+)")[1])
    except BaseException:
        proc.__exit__(None, None, None)
        raise
    return proc, port


def s_client(binary: str, port: int, pki: Pki, now: dt.datetime, keylog_file: Path, *extra: str) -> Process:
    return Process([binary, "s_client", "-connect", f"127.0.0.1:{port}", "-tls1_3", "-ciphersuites", SUITE,
                    "-CAfile", str(pki.root), "-verify_return_error", "-verify_hostname", "qtls.test",
                    "-servername", "qtls.test", "-attime", attime(now), "-keylogfile", str(keylog_file), *extra])  # fmt: skip


# --------------------------------------------------------------------------- #
# A recording relay (for captures)
# --------------------------------------------------------------------------- #


class Relay:
    """Forwards one TCP connection to ``upstream`` and records each direction's bytes in order."""

    def __init__(self, upstream: tuple[str, int]) -> None:
        self.upstream = upstream
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.from_client = bytearray()
        self.from_server = bytearray()
        self.error: BaseException | None = None
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        try:
            self.listener.settimeout(30)
            down, _ = self.listener.accept()
            up = socket.create_connection(self.upstream, timeout=30)
            pairs = {down: (up, self.from_client), up: (down, self.from_server)}
            open_ = {down, up}
            with selectors.DefaultSelector() as sel, down, up:
                for s in open_:
                    sel.register(s, selectors.EVENT_READ)
                while open_:
                    ready = sel.select(30)
                    if not ready:
                        raise TimeoutError("relay idle for 30 s")
                    for key, _ in ready:
                        src = key.fileobj
                        dst, log = pairs[src]  # type: ignore[index]
                        try:
                            data = src.recv(65536)  # type: ignore[union-attr]
                        except ConnectionResetError:
                            data = b""
                        if data:
                            log += data
                            dst.sendall(data)
                        else:
                            sel.unregister(src)
                            open_.discard(src)  # type: ignore[arg-type]
                            try:
                                dst.shutdown(socket.SHUT_WR)
                            except OSError:
                                pass
        except BaseException as exc:  # noqa: BLE001
            self.error = exc
        finally:
            self.listener.close()

    def join(self, timeout: float = 30) -> None:
        self._thread.join(timeout)
        if self._thread.is_alive():
            raise TimeoutError("relay didn't finish")
        if self.error is not None:
            raise self.error
