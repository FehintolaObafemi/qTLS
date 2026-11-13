"""Deterministic randomness for liboqs: thread-scoped, fail-closed, never leaking."""

from __future__ import annotations

import asyncio
import concurrent.futures
import gc
import threading

import pytest

from qtls import crypto
from qtls.crypto import RandomnessError

pytestmark = pytest.mark.usefixtures("require_liboqs")

ENTROPY = bytes(range(48))


def test_same_entropy_gives_same_output_and_system_rng_resumes() -> None:
    with crypto.deterministic_rng(ENTROPY):
        a = crypto.sig_generate("Falcon-512", "liboqs").public_key
    between = crypto.sig_generate("Falcon-512", "liboqs").public_key
    with crypto.deterministic_rng(ENTROPY):
        b = crypto.sig_generate("Falcon-512", "liboqs").public_key
    assert a == b
    assert between != a
    assert crypto.backend_info()["liboqs_rng"] == "system"


def test_rng_reported_while_active() -> None:
    with crypto.deterministic_rng(ENTROPY):
        assert crypto.backend_info()["liboqs_rng"] == "deterministic"
    assert crypto.backend_info()["liboqs_rng"] == "system"


def test_rng_restored_after_exception() -> None:
    with crypto.deterministic_rng(ENTROPY):
        pinned = crypto.kem_generate("ML-KEM-512", "liboqs").public_key
    with pytest.raises(ZeroDivisionError), crypto.deterministic_rng(ENTROPY):
        1 / 0  # noqa: B018
    a = crypto.kem_generate("ML-KEM-512", "liboqs").public_key
    b = crypto.kem_generate("ML-KEM-512", "liboqs").public_key
    assert a != b
    assert pinned not in (a, b)
    assert crypto.backend_info()["liboqs_rng"] == "system"


def test_nesting_raises_and_outer_block_is_unaffected() -> None:
    with crypto.deterministic_rng(ENTROPY):
        with pytest.raises(RandomnessError, match="nested"), crypto.deterministic_rng(ENTROPY):
            pass
        inside = crypto.sig_generate("Falcon-512", "liboqs").public_key
    with crypto.deterministic_rng(ENTROPY):
        reference = crypto.sig_generate("Falcon-512", "liboqs").public_key
    assert inside == reference


@pytest.mark.parametrize("delta", [-1, +1], ids=["under-supply", "over-supply"])
def test_fixed_randomness_must_be_consumed_exactly(delta: int) -> None:
    """ML-DSA keygen draws exactly ξ (32 bytes); anything else is refused and counted nowhere."""
    seed = bytes(range(32 + delta))
    message = "not consumed" if delta > 0 else "ran out"
    with crypto.count_ops() as ops, pytest.raises(RandomnessError, match=message):
        with crypto._fixed_randomness(seed):
            crypto._oqs().Signature("ML-DSA-44").generate_keypair()
    assert ops == {}
    assert crypto.backend_info()["liboqs_rng"] == "system"


def test_seeded_keygen_rejects_wrong_seed_lengths_and_types() -> None:
    for backend in crypto.BACKENDS:
        for alg in sorted(crypto.supported(backend)[1]):  # type: ignore[arg-type]
            n = crypto.SIGNATURES[alg].seed_len
            for bad in (bytes(n - 1), bytes(n + 1)):
                with pytest.raises(ValueError, match="seed"):
                    crypto.sig_generate(alg, backend, seed=bad)  # type: ignore[arg-type]
            with pytest.raises(TypeError):
                crypto.sig_generate(alg, backend, seed="x" * n)  # type: ignore[arg-type]


def test_a_failing_drbg_poisons_the_block(monkeypatch: pytest.MonkeyPatch) -> None:
    """An exception inside the C callback can't propagate; the block must still fail."""

    def boom(self: object, n: int) -> bytes:
        raise RuntimeError("drbg failure")

    monkeypatch.setattr(crypto._NistDrbg, "random", boom)
    with pytest.raises(RandomnessError, match="discarded"):
        with crypto.deterministic_rng(ENTROPY):
            crypto.kem_generate("ML-KEM-512", "liboqs")
    assert crypto.backend_info()["liboqs_rng"] == "system"


def test_other_threads_never_receive_deterministic_bytes() -> None:
    """A concurrent liboqs caller gets OS randomness, and doesn't eat the block's bytes."""
    stop = threading.Event()
    ciphertexts: list[bytes] = []
    peer = crypto.kem_generate("ML-KEM-768", "liboqs")

    def other_role() -> None:
        while not stop.is_set():
            ct, _ = crypto.kem_encapsulate("ML-KEM-768", peer.public_key, "liboqs")
            ciphertexts.append(ct)

    with crypto.deterministic_rng(ENTROPY):
        reference = crypto.sig_generate("Falcon-512", "liboqs").public_key
    thread = threading.Thread(target=other_role)
    thread.start()
    try:
        results = []
        for _ in range(20):
            with crypto.deterministic_rng(ENTROPY):
                results.append(crypto.sig_generate("Falcon-512", "liboqs").public_key)
            # An exactly-consumed fixed block also survives the concurrent caller.
            with crypto._fixed_randomness(bytes(32)):
                crypto._oqs().Signature("ML-DSA-44").generate_keypair()
    finally:
        stop.set()
        thread.join()
    assert set(results) == {reference}
    assert len(ciphertexts) > 0
    assert len(set(ciphertexts)) == len(ciphertexts)


def test_callback_survives_garbage_collection() -> None:
    with crypto.deterministic_rng(ENTROPY):
        gc.collect()
        a = crypto.sig_generate("Falcon-512", "liboqs").public_key
    gc.collect()
    with crypto.deterministic_rng(ENTROPY):
        b = crypto.sig_generate("Falcon-512", "liboqs").public_key
    assert a == b


def test_openssl_backend_is_unaffected_by_the_block() -> None:
    with crypto.deterministic_rng(ENTROPY):
        a = crypto.sig_generate("ML-DSA-44", "openssl").public_key
    with crypto.deterministic_rng(ENTROPY):
        b = crypto.sig_generate("ML-DSA-44", "openssl").public_key
    assert a != b


def test_deterministic_signing() -> None:
    msg = b"fixture"
    for alg in ("ML-DSA-44", "ML-DSA-65", "Falcon-512"):
        n = crypto.SIGNATURES[alg].sign_seed_len
        key = crypto.sig_generate(alg, "liboqs", seed=bytes(crypto.SIGNATURES[alg].seed_len))
        s1 = key.sign(msg, seed=bytes(n))
        s2 = key.sign(msg, seed=bytes(n))
        s3 = key.sign(msg, seed=b"\x01" * n)
        assert s1 == s2 != s3
        crypto.sig_verify(alg, key.public_key, msg, s1, "liboqs")
    ecdsa = crypto.sig_generate("ECDSA-P256-SHA256", "openssl", seed=b"\x01" * 32)
    assert ecdsa.sign(msg, seed=b"") == ecdsa.sign(msg, seed=b"")
    with pytest.raises(crypto.BackendUnavailable, match="deterministic"):
        crypto.sig_generate("ML-DSA-44", "openssl").sign(msg, seed=bytes(32))


def test_ecdsa_scalar_range() -> None:
    for bad in (bytes(32), crypto._P256_ORDER.to_bytes(32, "big"), b"\xff" * 32):
        with pytest.raises(ValueError, match="scalar"):
            crypto.sig_generate("ECDSA-P256-SHA256", "openssl", seed=bad)


def test_falcon_draw_counts_are_pinned() -> None:
    """How much randomness liboqs 0.16 draws; a library change must show up here."""
    with crypto.deterministic_rng(ENTROPY) as rng:
        key = crypto.sig_generate("Falcon-512", "liboqs")
        after_keygen = rng.bytes_served
        key.sign(b"m" * 33)
        after_sign = rng.bytes_served
    assert (after_keygen, after_sign - after_keygen) == FALCON_DRAWS


FALCON_DRAWS = (48, 88)  # (keygen, sign) bytes drawn under liboqs 0.16.0


def test_draw_after_exact_bytes_are_used_up_poisons_the_block() -> None:
    """32 bytes exactly cover one ML-DSA keygen; a second keygen over-draws."""
    with pytest.raises(RandomnessError, match="ran out"):
        with crypto._fixed_randomness(bytes(32)):
            signer = crypto._oqs().Signature("ML-DSA-44")
            signer.generate_keypair()
            signer.generate_keypair()


def _keygen_with_source_but_no_block() -> bytes:
    token = crypto._rng_owner.set(crypto.DeterministicSource(drbg=crypto._NistDrbg(ENTROPY)))
    try:
        return crypto._oqs().Signature("Falcon-512").generate_keypair()
    finally:
        crypto._rng_owner.reset(token)


def test_hook_is_uninstalled_after_the_block() -> None:
    """After exit liboqs must be back on its own RNG, not still routed through Python."""
    with crypto.deterministic_rng(ENTROPY):
        pass
    # If the callback were still installed, the context's source would be served.
    assert _keygen_with_source_but_no_block() != _keygen_with_source_but_no_block()


def test_hook_restore_is_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    """A failed restore of liboqs's system RNG is an error, not silently ignored."""
    native = crypto._oqs().native()
    real = native.OQS_randombytes_switch_algorithm
    calls: list[bytes] = []

    def failing_switch(name: object) -> int:
        calls.append(bytes(name.value))  # type: ignore[attr-defined]
        real(name)
        return -1

    monkeypatch.setattr(native, "OQS_randombytes_switch_algorithm", failing_switch)
    with pytest.raises(RandomnessError, match="system RNG"):
        with crypto.deterministic_rng(ENTROPY):
            pass
    assert calls == [b"system"]


# --------------------------------------------------------------------------- #
# Added after the Phase 2a change review
# --------------------------------------------------------------------------- #



def _falcon_fixture(seed: bytes) -> tuple[bytes, bytes]:
    key = crypto.sig_generate("Falcon-512", "liboqs", seed=seed)
    return key.public_key, key.sign(b"fixture", seed=seed)


def test_concurrent_blocks_in_different_threads_are_isolated() -> None:
    """Without isolation this produced wrong fixtures with no error (799/800 in review)."""
    seeds = [bytes([i]) * 48 for i in range(8)]
    reference = {s: _falcon_fixture(s) for s in seeds}
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        for _ in range(5):
            results = list(pool.map(_falcon_fixture, seeds))
            assert results == [reference[s] for s in seeds]


def test_sibling_asyncio_task_never_receives_block_bytes() -> None:
    """Ownership is per execution context, not per thread."""
    with crypto.deterministic_rng(ENTROPY):
        reference = crypto.kem_generate("ML-KEM-768", "liboqs").public_key

    async def holder(started: asyncio.Event, release: asyncio.Event) -> None:
        with crypto.deterministic_rng(ENTROPY):
            started.set()
            await release.wait()  # another task runs while this block is open
            crypto.kem_generate("ML-KEM-768", "liboqs")

    async def sibling(started: asyncio.Event, release: asyncio.Event) -> list[bytes]:
        await started.wait()
        keys = [crypto.kem_generate("ML-KEM-768", "liboqs").public_key for _ in range(2)]
        release.set()
        return keys

    async def main() -> list[bytes]:
        started, release = asyncio.Event(), asyncio.Event()
        _, keys = await asyncio.gather(holder(started, release), sibling(started, release))
        return keys

    keys = asyncio.run(main())
    assert keys[0] != keys[1]
    assert reference not in keys


def test_an_unexited_block_does_not_block_other_contexts() -> None:
    entered = threading.Event()
    release = threading.Event()

    def leaky() -> None:
        with crypto.deterministic_rng(ENTROPY):
            entered.set()
            release.wait(30)

    t = threading.Thread(target=leaky)
    t.start()
    try:
        assert entered.wait(10)
        done = concurrent.futures.ThreadPoolExecutor(1).submit(
            lambda: crypto.sig_generate("Falcon-512", "liboqs", seed=bytes(48)).public_key
        )
        assert done.result(timeout=10) == crypto.sig_generate("Falcon-512", "liboqs", seed=bytes(48)).public_key
        assert crypto.backend_info()["liboqs_rng"] == "system"  # this context isn't in a block
    finally:
        release.set()
        t.join()


def test_backend_info_records_that_a_block_ever_ran() -> None:
    before = int(crypto.backend_info()["liboqs_deterministic_blocks"])
    with crypto.deterministic_rng(ENTROPY):
        pass
    assert int(crypto.backend_info()["liboqs_deterministic_blocks"]) == before + 1


def test_failed_install_leaves_no_state(monkeypatch: pytest.MonkeyPatch) -> None:
    native = crypto._oqs().native()

    def broken(_cb: object) -> None:
        raise OSError("install failed")

    monkeypatch.setattr(native, "OQS_randombytes_custom_algorithm", broken)
    with pytest.raises(OSError), crypto.deterministic_rng(ENTROPY):
        pass
    monkeypatch.undo()
    assert crypto._rng_owner.get() is None
    assert crypto._rng_open_blocks == 0
    with crypto.deterministic_rng(ENTROPY):  # a fresh block in this context works
        crypto.kem_generate("ML-KEM-512", "liboqs")


def test_callback_copy_failure_poisons_the_block(monkeypatch: pytest.MonkeyPatch) -> None:
    real = crypto.ctypes.memmove
    state = {"failed": False}

    def flaky(dst: object, src: object, n: int) -> object:
        if not state["failed"]:
            state["failed"] = True
            raise RuntimeError("copy failed")
        return real(dst, src, n)

    monkeypatch.setattr(crypto.ctypes, "memmove", flaky)
    with pytest.raises(RandomnessError, match="ran out or failed"):
        crypto.sig_generate("ML-DSA-44", "liboqs", seed=bytes(32))
    assert state["failed"]


def test_liboqs_handles_are_freed_when_seeded_keygen_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    freed: list[object] = []
    real_free = crypto._free
    monkeypatch.setattr(crypto, "_free", lambda h: (freed.append(h), real_free(h)))
    monkeypatch.setattr(crypto._NistDrbg, "random", lambda self, n: (_ for _ in ()).throw(RuntimeError()))
    with pytest.raises(RandomnessError):
        crypto.sig_generate("Falcon-512", "liboqs", seed=bytes(48))
    assert len(freed) == 1


def test_sign_rejects_wrong_seed_lengths() -> None:
    for backend in crypto.BACKENDS:
        for alg in sorted(crypto.supported(backend)[1]):  # type: ignore[arg-type]
            params = crypto.SIGNATURES[alg]
            key = crypto.sig_generate(alg, backend)  # type: ignore[arg-type]
            for bad in (bytes(params.sign_seed_len + 1), b"x" * (params.sign_seed_len - 1) if params.sign_seed_len else b"x"):
                with pytest.raises(ValueError, match="seed"):
                    key.sign(b"m", seed=bad)


def test_seeded_mldsa_signing_matches_the_kat_path() -> None:
    """FIPS 204 hedged signing: keygen draws ξ, then signing draws rnd, from one DRBG stream."""
    seed = bytes(range(48))
    msg = b"pinned message"
    for alg in ("ML-DSA-44", "ML-DSA-65"):
        with crypto.deterministic_rng(seed):
            kat_key = crypto.sig_generate(alg, "liboqs")
            kat_sig = kat_key.sign(msg)
        drbg = crypto._NistDrbg(seed)
        xi, rnd = drbg.random(32), drbg.random(32)
        key = crypto.sig_generate(alg, "liboqs", seed=xi)
        assert key.public_key == kat_key.public_key
        assert key.sign(msg, seed=rnd) == kat_sig
        crypto.sig_verify(alg, crypto.sig_generate(alg, "openssl", seed=xi).public_key, msg, kat_sig, "openssl")


def test_falcon_seeded_signing_never_reuses_a_salt_across_messages() -> None:
    key = crypto.sig_generate("Falcon-512", "liboqs", seed=bytes(48))
    a, b = key.sign(b"message one", seed=bytes(48)), key.sign(b"message two", seed=bytes(48))
    assert a[1:41] != b[1:41]  # the 40-byte salt after the header byte
    assert key.sign(b"message one", seed=bytes(48)) == a


def test_seeded_encapsulation_maps_invalid_keys_like_unseeded() -> None:
    with pytest.raises(crypto.InvalidPublicKey):
        crypto.kem_encapsulate("ML-KEM-768", b"\xff" * 1184, "liboqs", seed=bytes(32))


def test_seeded_operations_are_counted() -> None:
    with crypto.count_ops() as ops:
        key = crypto.sig_generate("ML-DSA-44", "liboqs", seed=bytes(32))
        key.sign(b"m", seed=bytes(32))
        kem = crypto.kem_generate("ML-KEM-768", "liboqs", seed=bytes(64))
        crypto.kem_encapsulate("ML-KEM-768", kem.public_key, "liboqs", seed=bytes(32))
    assert ops == {
        ("liboqs", "ML-DSA-44", "keygen"): 1,
        ("liboqs", "ML-DSA-44", "sign"): 1,
        ("liboqs", "ML-KEM-768", "keygen"): 1,
        ("liboqs", "ML-KEM-768", "encap"): 1,
    }


def test_ecdsa_scalar_boundaries_and_randomised_default() -> None:
    for ok in (1, crypto._P256_ORDER - 1):
        crypto.sig_generate("ECDSA-P256-SHA256", "openssl", seed=ok.to_bytes(32, "big"))
    key = crypto.sig_generate("ECDSA-P256-SHA256", "openssl", seed=b"\x01" * 32)
    assert key.sign(b"m") != key.sign(b"m")


def test_a_task_created_inside_a_block_is_random_after_the_block_exits() -> None:
    """A copied context keeps the source object; once closed it must act like none."""
    other_open = threading.Event()
    release = threading.Event()

    def other_context_block() -> None:
        with crypto.deterministic_rng(bytes(48)):
            other_open.set()
            release.wait(30)

    async def main() -> tuple[list[bytes], str, int]:
        with crypto.deterministic_rng(ENTROPY) as source:
            task_started = asyncio.Event()
            proceed = asyncio.Event()

            async def child() -> tuple[list[bytes], str]:
                task_started.set()
                await proceed.wait()
                keys = [crypto.sig_generate("ML-DSA-44", "liboqs").public_key for _ in range(2)]
                mode = crypto.backend_info()["liboqs_rng"]
                with crypto.deterministic_rng(ENTROPY):  # may open its own block
                    pass
                return keys, mode

            task = asyncio.create_task(child())
            await task_started.wait()
        # The block has exited; keep another context's block open meanwhile.
        thread = threading.Thread(target=other_context_block)
        thread.start()
        try:
            assert other_open.wait(10)
            proceed.set()
            keys, mode = await task
        finally:
            release.set()
            thread.join()
        return keys, mode, source.bytes_served

    keys, mode, served = asyncio.run(main())
    assert keys[0] != keys[1]
    assert mode == "system"
    assert served == 0


def test_falcon_seeded_signing_is_bound_to_the_key() -> None:
    """Same seed and message under two different keys must not share a salt."""
    a = crypto.sig_generate("Falcon-512", "liboqs", seed=bytes(48))
    b = crypto.sig_generate("Falcon-512", "liboqs", seed=b"\x01" * 48)
    sig_a, sig_b = a.sign(b"same", seed=bytes(48)), b.sign(b"same", seed=bytes(48))
    assert sig_a[1:41] != sig_b[1:41]


def test_liboqs_kem_handle_is_freed_when_keygen_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    freed: list[object] = []
    real_free = crypto._free
    monkeypatch.setattr(crypto, "_free", lambda h: (freed.append(h), real_free(h)))
    oqs = crypto._oqs()
    monkeypatch.setattr(oqs.KeyEncapsulation, "generate_keypair_seed",
                        lambda self, seed: (_ for _ in ()).throw(RuntimeError("keygen failed")))
    with pytest.raises(RuntimeError, match="keygen failed"):
        crypto.kem_generate("ML-KEM-768", "liboqs", seed=bytes(64))
    assert len(freed) == 1
