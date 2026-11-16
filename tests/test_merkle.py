"""Merkle subtrees and proofs against MTC -08's own vectors (specs.md D31).

Oracles, all independent of qtls/merkle.py:

* Appendix C.1: accumulated digests over every subtree, proof and covering of
  trees up to 130 entries, and the relying-party checks C.1.2 and C.1.3 ask
  for (truncate, extend, flip).
* Appendix C.2: large trees up to 2^64 − 1, from the draft text and from the
  WG repository's JSON at the -08 tag (tests/vectors/mtc/SOURCE).
* A reference Merkle Tree Hash written here from RFC 9162 §2.1.1 with
  hashlib, which the relying-party checks compare against, so the module's
  builder can't vouch for its own verifier.
* The worked examples in §4.3.1, §4.4.2 and §4.5.
"""

from __future__ import annotations

import base64
import hashlib
import json
import random
from collections.abc import Callable
from functools import cache
from pathlib import Path

import pytest

from qtls import merkle
from qtls.alerts import CodecUsageError

VECTORS = Path(__file__).parent / "vectors" / "mtc"
APPENDIX_C = json.loads((VECTORS / "appendix_c.json").read_text())
LARGE_INCLUSION = json.loads((VECTORS / "large_inclusion_proofs.json").read_text())
LARGE_CONSISTENCY = json.loads((VECTORS / "large_consistency_proofs.json").read_text())

MAX = 130  # Appendix C.1 covers trees of up to 130 entries
D = [bytes([i]) for i in range(MAX + 1)]  # d[0] = 0x00, d[1] = 0x01, ... (C.1)
TREE = merkle.Tree.from_entries(D)


def ev(start: int, end: int, index: int, entry_hash: bytes, proof: bytes) -> bytes:
    """Positional shorthands for the keyword-only verifier, in each function's step order."""
    return merkle.evaluate_inclusion_proof(start=start, end=end, index=index, entry_hash=entry_hash, proof=proof)


def vi(start: int, end: int, index: int, entry_hash: bytes, proof: bytes, subtree_hash: bytes) -> None:
    merkle.verify_inclusion(start=start, end=end, index=index, entry_hash=entry_hash, proof=proof, subtree_hash=subtree_hash)


def vc(n: int, start: int, end: int, proof: bytes, subtree_hash: bytes, root_hash: bytes) -> None:
    merkle.verify_consistency(n=n, start=start, end=end, proof=proof, subtree_hash=subtree_hash, root_hash=root_hash)


def b64(s: str) -> bytes:
    return base64.b64decode(s, validate=True)


# --------------------------------------------------------------------------- #
# A reference MTH, from RFC 9162 §2.1.1 alone
# --------------------------------------------------------------------------- #


@cache
def ref_mth(start: int, end: int) -> bytes:
    """MTH(D[start:end]) for the C.1 entries, straight from RFC 9162's recursion."""
    n = end - start
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return hashlib.sha256(b"\x00" + D[start]).digest()
    k = 1
    while k * 2 < n:
        k *= 2
    return hashlib.sha256(b"\x01" + ref_mth(start, start + k) + ref_mth(start + k, end)).digest()


def subtrees(limit: int = MAX) -> list[tuple[int, int]]:
    """Every valid subtree with end <= limit, in C.1's order."""
    return [(s, e) for e in range(limit + 1) for s in range(e + 1) if merkle.valid_subtree(s, e)]


def ref_valid(start: int, end: int) -> bool:
    """MTC -08 §4.1 by brute force: start is a multiple of the smallest power of two >= size."""
    size, p = end - start, 1
    while p < size:
        p *= 2
    return 0 <= start <= end and start % p == 0


def hexes(proof: bytes) -> str:
    return "".join(" " + proof[i : i + 32].hex() for i in range(0, len(proof), 32))


def flip(value: bytes, bit: int = 0) -> bytes:
    out = bytearray(value)
    out[bit // 8] ^= 0x80 >> (bit % 8)
    return bytes(out)


def accumulate(lines: list[str]) -> str:
    h = hashlib.sha256()
    for line in lines:
        h.update(f"{line}\n".encode())
    return h.hexdigest()


# --------------------------------------------------------------------------- #
# Appendix C.1: accumulated vectors and the relying-party checks
# --------------------------------------------------------------------------- #


def test_validity_matches_the_definition_for_small_trees() -> None:
    for end in range(MAX + 1):
        for start in range(-2, end + 3):
            assert merkle.valid_subtree(start, end) == ref_valid(start, end), (start, end)


def test_c11_subtree_hashes() -> None:
    lines = []
    for start, end in subtrees():
        h = TREE.hash(start, end)
        assert h == ref_mth(start, end)
        lines.append(f"[{start}, {end}) {h.hex()}")
    assert accumulate(lines) == APPENDIX_C["accumulated"]["C.1.1"]


def reason(call: Callable[[], object]) -> str:
    """The MerkleError reason ``call`` raises (it must raise one)."""
    with pytest.raises(merkle.MerkleError) as info:
        call()
    return info.value.reason


def test_c12_inclusion_proofs() -> None:
    lines = []
    extra = hashlib.sha256(b"an arbitrary hash").digest()
    for start, end in subtrees():
        for index in range(start, end):
            proof = TREE.inclusion_proof(start, end, index)
            lines.append(f"{index} [{start}, {end}){hexes(proof)}")
            entry, root = ref_mth(index, index + 1), ref_mth(start, end)
            assert ev(start, end, index, entry, proof) == root
            vi(start, end, index, entry, proof, root)
            assert reason(lambda: ev(start, end, index, entry, proof + b"\x00")) == "ragged"
            assert reason(lambda: ev(start, end, index, entry, proof + extra)) == "too-long"
            if proof:
                assert reason(lambda: ev(start, end, index, entry, proof[:-1])) == "ragged"
                assert reason(lambda: ev(start, end, index, entry, proof[:-32])) == "too-short"
            # §4.3.3 step 2: verify_inclusion itself must compare
            assert reason(lambda: vi(start, end, index, entry, proof, flip(root, 9))) == "subtree-mismatch"
            assert reason(lambda: vi(start, end, index, flip(entry, 9), proof, root)) == "subtree-mismatch"
    assert accumulate(lines) == APPENDIX_C["accumulated"]["C.1.2"]


@pytest.mark.parametrize("chunk", range(5), ids=lambda c: f"n%5=={c}")
def test_c13_consistency_proofs(chunk: int) -> None:
    """Split by n so a failure names a smaller slice; the digest is checked over all of them below."""
    extra = hashlib.sha256(b"an arbitrary hash").digest()
    other = hashlib.sha256(b"any tree").digest()
    for n in range(chunk, MAX + 1, 5):
        root = ref_mth(0, n)
        for start, end in subtrees(n):
            proof = TREE.consistency_proof(start, end, n)
            node = ref_mth(start, end)
            vc(n, start, end, proof, node, root)
            assert reason(lambda: vc(n, start, end, proof + b"\x00", node, root)) == "ragged"
            if start == end:  # §4.4.3 step 2: empty proof, HASH(), and any tree hash
                vc(n, start, end, proof, node, other)
                assert reason(lambda: vc(n, start, end, extra, node, root)) == "empty-subtree"
                assert reason(lambda: vc(n, start, end, proof, flip(node, 7), root)) == "empty-subtree"
                continue
            assert reason(lambda: vc(n, start, end, proof + extra, node, root)) == "too-long"
            # §4.4.1: the proof omits the subtree's own hash exactly when the subtree is full or ends
            # at n; then fr starts from the given hash and a wrong one surfaces at the tree hash.
            omitted = (end - start) & (end - start - 1) == 0 or end == n
            expected = "root-mismatch" if omitted else "subtree-mismatch"
            assert reason(lambda: vc(n, start, end, proof, flip(node, 7), root)) == expected
            assert reason(lambda: vc(n, start, end, proof, node, flip(root, 255))) == "root-mismatch"
            if proof:
                assert reason(lambda: vc(n, start, end, proof[:-1], node, root)) == "ragged"
                assert reason(lambda: vc(n, start, end, proof[:-32], node, root)) == "too-short"


def test_c13_consistency_proofs_digest() -> None:
    lines = []
    for n in range(MAX + 1):
        for start, end in subtrees(n):
            lines.append(f"[{start}, {end}) {n}{hexes(TREE.consistency_proof(start, end, n))}")
    assert accumulate(lines) == APPENDIX_C["accumulated"]["C.1.3"]


def test_c14_covering_subtrees() -> None:
    lines = []
    for end in range(MAX + 1):
        for start in range(end + 1):
            (ls, le), (rs, re_) = merkle.find_subtrees(start, end)
            # §4.5.1's guarantees, checked independently of the digest
            assert ref_valid(ls, le) and ref_valid(rs, re_)
            assert ls <= start <= le == rs <= end == re_
            assert max(le - ls, re_ - rs) <= max(1, merkle.bit_ceil(end - start))
            lines.append(f"[{ls}, {le}) [{rs}, {re_})")
    assert accumulate(lines) == APPENDIX_C["accumulated"]["C.1.4"]


# --------------------------------------------------------------------------- #
# Appendix C.2: large trees
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(("start", "end"), APPENDIX_C["valid_subtrees"], ids=str)
def test_c21_large_valid_subtrees(start: int, end: int) -> None:
    assert merkle.valid_subtree(start, end)


@pytest.mark.parametrize(("start", "end"), APPENDIX_C["invalid_subtrees"], ids=str)
def test_c21_large_invalid_subtrees(start: int, end: int) -> None:
    assert not merkle.valid_subtree(start, end)


def test_c2_vector_counts() -> None:
    """Guards the vendored files: all of C.2.2, C.2.3 and C.2.4 (every case is a positive one)."""
    assert (len(LARGE_INCLUSION), len(LARGE_CONSISTENCY), len(APPENDIX_C["covering"])) == (24, 21, 15)


@pytest.mark.parametrize("v", LARGE_INCLUSION, ids=lambda v: f"{v['Index']}@[{v['Start']},{v['End']})")
def test_c22_large_inclusion_proofs(v: dict) -> None:
    start, end, index = int(v["Start"]), int(v["End"]), int(v["Index"])
    entry, subtree, proof = b64(v["EntryHash"]), b64(v["SubtreeHash"]), b64(v["Proof"])
    vi(start, end, index, entry, proof, subtree)
    for k in range(len(proof) // 32):  # one flip in each hash, at a rotating position
        bad = flip(proof, k * 256 + (k * 37) % 256)
        assert reason(lambda: vi(start, end, index, entry, bad, subtree)) == "subtree-mismatch"
    assert reason(lambda: vi(start, end, index, flip(entry), proof, subtree)) == "subtree-mismatch"
    assert reason(lambda: ev(start, end, index, entry, proof + proof[:32])) == "too-long"
    assert reason(lambda: ev(start, end, index, entry, proof[:-1])) == "ragged"
    if proof:
        assert reason(lambda: ev(start, end, index, entry, proof[:-32])) == "too-short"
    # The aliased index of the same position one subtree-width along (§4.3.2 step 1; D31)
    width = merkle.bit_ceil(end - start)
    for alias in (index + width, index - width, end, start - 1, index + 2**48, index + 2**64):
        if not start <= alias < end:
            assert reason(lambda: ev(start, end, alias, entry, proof)) == "index-range"


@pytest.mark.parametrize("v", LARGE_CONSISTENCY, ids=lambda v: f"[{v['Start']},{v['End']})/{v['TreeSize']}")
def test_c23_large_consistency_proofs(v: dict) -> None:
    start, end, n = int(v["Start"]), int(v["End"]), int(v["TreeSize"])
    node, root, proof = b64(v["SubtreeHash"]), b64(v["TreeHash"]), b64(v["Proof"])
    vc(n, start, end, proof, node, root)
    for k in range(len(proof) // 32):
        with pytest.raises(merkle.MerkleError):
            vc(n, start, end, flip(proof, k * 256 + (k * 37) % 256), node, root)
    with pytest.raises(merkle.MerkleError):
        vc(n, start, end, proof + node, node, root)
    if start != end:
        assert reason(lambda: vc(n, start, end, proof, node, flip(root))) == "root-mismatch"
        with pytest.raises(merkle.MerkleError):
            vc(n, start, end, proof, flip(node), root)
    if proof:
        assert reason(lambda: vc(n, start, end, proof[:-32], node, root)) == "too-short"
    if end:
        assert reason(lambda: vc(end - 1, start, end, proof, node, root)) == "end-beyond-tree"


def test_c2_vector_files_cover_the_three_bounds() -> None:
    """C.2: trees bounded by 2^48 − 1, 2^63 − 1 and 2^64 − 1, so a 64-bit overflow bug would show."""
    widths = {int(v["End"]).bit_length() for v in LARGE_INCLUSION}
    widths |= {int(v["TreeSize"]).bit_length() for v in LARGE_CONSISTENCY}
    assert widths == {48, 63, 64}


@pytest.mark.parametrize("v", APPENDIX_C["covering"], ids=lambda v: f"[{v['range'][0]:#x},{v['range'][1]:#x})")
def test_c24_large_covering_subtrees(v: dict) -> None:
    left, right = merkle.find_subtrees(*v["range"])
    assert [list(left), list(right)] == [v["left"], v["right"]]


# --------------------------------------------------------------------------- #
# Worked examples (§4.3.1, §4.4.2, §4.5)
# --------------------------------------------------------------------------- #


def test_figure_6_inclusion_proof_for_entry_10_of_8_13() -> None:
    assert TREE.inclusion_proof(8, 13, 10) == ref_mth(11, 12) + ref_mth(8, 10) + ref_mth(12, 13)


def test_figure_7_consistency_proof_for_4_8_in_14() -> None:
    assert TREE.consistency_proof(4, 8, 14) == ref_mth(0, 4) + ref_mth(8, 14)


def test_figure_8_consistency_proof_for_8_13_in_14() -> None:
    assert TREE.consistency_proof(8, 13, 14) == ref_mth(12, 13) + ref_mth(13, 14) + ref_mth(8, 12) + ref_mth(0, 8)


def test_section_4_5_covering_examples() -> None:
    assert merkle.find_subtrees(5, 13) == ((4, 8), (8, 13))  # Figure 10
    assert merkle.find_subtrees(7, 9) == ((7, 8), (8, 9))  # Figure 9's interval, covered by two small subtrees


def test_section_4_1_special_cases() -> None:
    for x in (0, 1, 7, 2**48 - 1, 2**64):
        assert merkle.valid_subtree(0, x)  # [0, x) is always valid
        assert merkle.valid_subtree(x, x)  # and so is [x, x)
    assert not merkle.valid_subtree(1, 0)
    assert not merkle.valid_subtree(-1, 0)


def test_rfc_9162_special_cases_of_subtree_proofs() -> None:
    """§4.4.1: start = 0 gives RFC 9162's PROOF, and a one-entry subtree gives its PATH."""
    for n in range(1, 40):
        for end in range(1, n + 1):
            p = TREE.consistency_proof(0, end, n)
            vc(n, 0, end, p, ref_mth(0, end), ref_mth(0, n))
        for i in range(n):
            assert TREE.consistency_proof(i, i + 1, n) == TREE.inclusion_proof(0, n, i)


# --------------------------------------------------------------------------- #
# Domain separation and node order (mutants must fail the vectors)
# --------------------------------------------------------------------------- #


def _sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


MUTANTS: dict[str, tuple[Callable[[bytes], bytes], Callable[[bytes, bytes], bytes]]] = {
    "leaf-without-0x00": (lambda e: _sha(e), lambda l, r: _sha(b"\x01" + l + r)),
    "node-without-0x01": (lambda e: _sha(b"\x00" + e), lambda l, r: _sha(l + r)),
    "prefixes-swapped": (lambda e: _sha(b"\x01" + e), lambda l, r: _sha(b"\x00" + l + r)),
    "children-swapped": (lambda e: _sha(b"\x00" + e), lambda l, r: _sha(b"\x01" + r + l)),
}


def test_empty_hash_mutant_fails_the_vectors(monkeypatch: pytest.MonkeyPatch) -> None:
    """EMPTY must be HASH(""), not HASH(0x00): C.1.1 hashes [x, x) for every x."""
    monkeypatch.setattr(merkle, "empty_hash", lambda: _sha(b"\x00"))
    lines = [f"[{s}, {e}) {merkle.Tree.from_entries(D).hash(s, e).hex()}" for s, e in subtrees()]
    assert accumulate(lines) != APPENDIX_C["accumulated"]["C.1.1"]
    v = next(v for v in LARGE_CONSISTENCY if v["Start"] == v["End"])
    with pytest.raises(merkle.MerkleError):
        vc(int(v["TreeSize"]), int(v["Start"]), int(v["End"]), b64(v["Proof"]), b64(v["SubtreeHash"]), b64(v["TreeHash"]))


@pytest.mark.parametrize("name", MUTANTS)
def test_domain_separation_mutants_fail_the_vectors(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    leaf, node = MUTANTS[name]
    monkeypatch.setattr(merkle, "leaf_hash", leaf)
    monkeypatch.setattr(merkle, "node_hash", node)
    tree = merkle.Tree.from_entries(D)
    lines = [f"[{s}, {e}) {tree.hash(s, e).hex()}" for s, e in subtrees()]
    assert accumulate(lines) != APPENDIX_C["accumulated"]["C.1.1"]
    if name == "leaf-without-0x00":
        return  # C.2 vectors give the entry hash, so only C.1 sees how leaves are hashed
    v = LARGE_INCLUSION[0]
    with pytest.raises(merkle.MerkleError):
        vi(int(v["Start"]), int(v["End"]), int(v["Index"]), b64(v["EntryHash"]),
                                b64(v["Proof"]), b64(v["SubtreeHash"]))  # fmt: skip


# --------------------------------------------------------------------------- #
# Untrusted input: only MerkleError, never a crash or a hang
# --------------------------------------------------------------------------- #


def test_verifier_rejects_garbage_with_merkle_error_only() -> None:
    rng = random.Random(20261115)
    edges = [0, 1, 2, 3, 7, 8, 13, 2**47, 2**48 - 1, 2**48, 2**63, 2**64 - 1, 2**64, -1]
    h = _sha(b"x")
    for _ in range(4000):
        start, end, index, n = (rng.choice(edges) if rng.random() < 0.5 else rng.randrange(0, 300) for _ in range(4))
        proof = rng.randbytes(rng.choice([0, 1, 31, 32, 33, 64, 32 * rng.randrange(0, 70)]))
        try:
            ev(start, end, index, h, proof)
        except merkle.MerkleError:
            pass
        try:
            vc(n, start, end, proof, h, h)
        except merkle.MerkleError:
            pass


@pytest.mark.parametrize(
    ("start", "end", "index"),
    [(1, 3, 1), (0, 4, 4), (4, 8, 3), (-1, 1, 0), (2, 1, 1), (0, 0, 0), (3, 3, 3)],
    ids=str,
)
def test_inclusion_needs_a_valid_subtree_containing_the_index(start: int, end: int, index: int) -> None:
    with pytest.raises(merkle.MerkleError):
        ev(start, end, index, _sha(b"x"), b"")


@pytest.mark.parametrize(("n", "start", "end"), [(3, 1, 3), (3, 0, 4), (5, -1, 0), (0, 1, 1)], ids=str)
def test_consistency_needs_a_valid_subtree_inside_the_tree(n: int, start: int, end: int) -> None:
    with pytest.raises(merkle.MerkleError):
        vc(n, start, end, b"", merkle.empty_hash(), merkle.empty_hash())


def test_empty_subtree_consistency() -> None:
    """§4.4.3 step 2: an empty subtree needs an empty proof and HASH(); the tree hash isn't consulted."""
    e = merkle.empty_hash()
    assert e == hashlib.sha256(b"").digest()
    vc(10, 4, 4, b"", e, _sha(b"any tree"))
    with pytest.raises(merkle.MerkleError):
        vc(10, 4, 4, e, e, e)
    with pytest.raises(merkle.MerkleError):
        vc(10, 4, 4, b"", _sha(b"not empty"), e)


def test_one_entry_subtree_inclusion_has_an_empty_proof() -> None:
    entry = ref_mth(5, 6)
    assert TREE.inclusion_proof(5, 6, 5) == b""
    assert ev(5, 6, 5, entry, b"") == entry


# --------------------------------------------------------------------------- #
# Local misuse: CodecUsageError, not a verification failure
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "call",
    [
        lambda: TREE.hash(0, MAX + 2),
        lambda: TREE.hash(3, 2),
        lambda: TREE.inclusion_proof(1, 3, 1),
        lambda: TREE.inclusion_proof(0, 4, 4),
        lambda: TREE.inclusion_proof(128, 132, 128),
        lambda: TREE.consistency_proof(1, 3, 4),
        lambda: TREE.consistency_proof(0, 4, 3),
        lambda: TREE.consistency_proof(0, 4, MAX + 2),
        lambda: merkle.Tree(1, {0: b"short"}),
        lambda: merkle.Tree(2, {0: _sha(b"")}),  # a gap and no filler
        lambda: merkle.Tree(2, {2: _sha(b"")}, _sha(b"f")),  # a leaf outside the tree
        lambda: merkle.Tree(2, {}, b"short"),
        lambda: merkle.Tree(-1, {}, _sha(b"f")),
        lambda: merkle.Tree(2, {-1: _sha(b"")}, _sha(b"f")),
        lambda: TREE.hash(-1, 3),
        lambda: merkle.Tree(4, {0: _sha(b"")}, _sha(b"f")).hash(-1, 3),
        lambda: merkle.find_subtrees(3, 2),
        lambda: ev(0, 1, 0, b"short", b""),
        lambda: vi(0, 1, 0, _sha(b""), b"", b"short"),
        lambda: vc(1, 0, 1, b"", b"short", _sha(b"")),
        lambda: vc(1, 0, 1, b"", _sha(b""), b"short"),
    ],
    ids=range(21),
)
def test_local_misuse_is_a_usage_error(call: Callable[[], object]) -> None:
    with pytest.raises(CodecUsageError):
        call()


# --------------------------------------------------------------------------- #
# Sparse logs (a few real entries in a log of null_entry filler)
# --------------------------------------------------------------------------- #

FILLER = merkle.leaf_hash(b"\x00\x00\x00\x00")  # an MTCLogEntry: no extensions, null_entry (3b)


@pytest.mark.parametrize("seed", range(6))
def test_sparse_tree_equals_the_dense_tree(seed: int) -> None:
    """Every hash and proof of a sparse tree is the dense tree's over the same leaves."""
    rng = random.Random(seed)
    for size in (0, 1, 2, 3, 5, 8, 13, 31, 32, 33, 64, 100):
        real = {i: _sha(bytes([seed, i])) for i in range(size) if rng.random() < 0.3}
        sparse = merkle.Tree(size, real, FILLER)
        dense = merkle.Tree(size, {i: real.get(i, FILLER) for i in range(size)})
        for start, end in subtrees(size):
            assert sparse.hash(start, end) == dense.hash(start, end)
            for index in range(start, end):
                assert sparse.inclusion_proof(start, end, index) == dense.inclusion_proof(start, end, index)
        for n in range(size + 1):
            for start, end in subtrees(n):
                assert sparse.consistency_proof(start, end, n) == dense.consistency_proof(start, end, n)


def test_landmark_depth_proofs_are_cheap_in_a_sparse_log() -> None:
    """D14: a 23-hash proof needs a subtree of more than 2^22 entries; a sparse log builds it
    with a few hundred hashes, not millions."""
    from qtls import crypto

    size = 2**22 + 1
    entry = _sha(b"the one real certificate")
    with crypto.count_ops() as ops:
        tree = merkle.Tree(size, {0: entry}, FILLER)
        proof = tree.inclusion_proof(0, size, 0)
        root = tree.hash(0, size)
    assert len(proof) == 23 * 32
    assert ops[("openssl", "SHA-256", "merkle-digest")] < 200
    vi(0, size, 0, entry, proof, root)


def test_the_largest_mtc_log_is_sparse_too() -> None:
    """A log of 2^48 − 1 entries (MTCProof's uint48 bound) with entries at both ends."""
    size = 2**48 - 1
    first, last = _sha(b"first"), _sha(b"last")
    tree = merkle.Tree(size, {0: first, size - 1: last}, FILLER)
    root = tree.hash(0, size)
    for index, leaf in ((0, first), (size - 1, last)):
        vi(0, size, index, leaf, tree.inclusion_proof(0, size, index), root)
    (ls, le), (rs, re_) = merkle.find_subtrees(2**47 + 5, size)
    vc(size, rs, re_, tree.consistency_proof(rs, re_, size), tree.hash(rs, re_), root)
    vc(size, ls, le, tree.consistency_proof(ls, le, size), tree.hash(ls, le), root)


def test_merkle_hashing_is_counted_apart_from_transcripts() -> None:
    """Each node of a k-hash proof is one counted Merkle digest (Phase 5 attributes MTC cost)."""
    from qtls import crypto

    tree = merkle.Tree.from_entries(D[:13])
    proof = tree.inclusion_proof(8, 13, 10)
    with crypto.count_ops() as ops:
        ev(8, 13, 10, ref_mth(10, 11), proof)
    assert ops[("openssl", "SHA-256", "merkle-digest")] == len(proof) // 32 == 3
    assert ops[("openssl", "SHA-256", "merkle-bytes")] == 3 * 65  # 0x01 ‖ left ‖ right
    assert ops[("openssl", "SHA-256", "digest")] == 0


# --------------------------------------------------------------------------- #
# Parameter tampering: a proof that verifies must not verify for other parameters
# --------------------------------------------------------------------------- #


def test_inclusion_index_must_be_in_the_subtree() -> None:
    """§4.3.2 step 1. Without it, index + BIT_CEIL(size) verifies with index's proof, and since the
    index is the serial's low 48 bits, a certificate would verify under an aliased serial (MTC §7.2)."""
    for start, end in subtrees(64):
        if start == end:
            continue
        width = merkle.bit_ceil(end - start)
        for index in range(start, end):
            proof, entry = TREE.inclusion_proof(start, end, index), ref_mth(index, index + 1)
            for alias in (index + width, index - width, end, start - 1, -1, end + 2**48):
                if not start <= alias < end:
                    assert reason(lambda: ev(start, end, alias, entry, proof)) == "index-range"


def test_inclusion_on_an_interval_that_is_not_a_subtree() -> None:
    """[1, 3) has a perfectly good RFC 9162 path, but it isn't a subtree (§4.1)."""
    for start, end in ((1, 3), (2, 5), (3, 7)):
        sub = merkle.Tree(end - start, {i - start: ref_mth(i, i + 1) for i in range(start, end)})
        proof = sub.inclusion_proof(0, end - start, 0)
        assert reason(lambda: ev(start, end, start, ref_mth(start, start + 1), proof)) == "not-subtree"


def test_consistency_end_beyond_the_tree() -> None:
    for n, start, end in ((3, 0, 4), (1, 0, 2), (6, 4, 8)):
        proof = TREE.consistency_proof(start, end, end)
        assert reason(lambda: vc(n, start, end, proof, ref_mth(start, end), ref_mth(0, end))) == "end-beyond-tree"


def test_consistency_on_an_interval_that_is_not_a_subtree() -> None:
    assert reason(lambda: vc(4, 1, 3, ref_mth(0, 1) + ref_mth(3, 4), ref_mth(1, 3), ref_mth(0, 4))) == "not-subtree"


@pytest.mark.parametrize(("start", "end", "n", "wrong_n"), [(0, 1, 1, 2), (0, 2, 2, 3), (0, 4, 4, 5), (4, 8, 8, 9)])
def test_consistency_tree_size_must_be_used_up(start: int, end: int, n: int, wrong_n: int) -> None:
    """§4.4.3 step 9's tn == 0: a proof for a tree of n doesn't pass for a larger tree."""
    proof = TREE.consistency_proof(start, end, n)
    assert reason(lambda: vc(wrong_n, start, end, proof, ref_mth(start, end), ref_mth(0, n))) == "too-short"


def test_what_proofs_do_not_bind() -> None:
    """Correct per §4, and why 3b must bind (n, root) and (start, end) elsewhere: from one
    authenticated source (a cosigned checkpoint or a trusted subtree), never from the proof."""
    # An inclusion proof doesn't fix the subtree's end: entry 0's proof in [0, 3), evaluated as
    # [0, 4), yields MTH(D[0:3]).
    proof = TREE.inclusion_proof(0, 3, 0)
    assert ev(0, 4, 0, ref_mth(0, 1), proof) == ref_mth(0, 3)
    # A consistency proof doesn't fix n: [0, 1) in a tree of 3 also passes as a tree of 4.
    p = TREE.consistency_proof(0, 1, 3)
    vc(4, 0, 1, p, ref_mth(0, 1), ref_mth(0, 3))


# --------------------------------------------------------------------------- #
# Validity, covering, cost, structure
# --------------------------------------------------------------------------- #


def test_validity_matches_the_definition_including_negatives() -> None:
    for end in range(-8, 301):
        for start in range(-8, end + 1):
            assert merkle.valid_subtree(start, end) == (start >= 0 and ref_valid(start, end)), (start, end)
    assert all(merkle.valid_subtree(x, x) for x in range(1, 300, 2))  # BIT_CEIL(0) is 1


def test_covering_invariants_for_large_random_intervals() -> None:
    rng = random.Random(4)
    for _ in range(10000):
        end = rng.randrange(0, 2**64)
        start = end - rng.randrange(0, min(end, 2 ** rng.randrange(1, 64)) + 1)
        (ls, le), (rs, re_) = merkle.find_subtrees(start, end)
        assert merkle.valid_subtree(ls, le) and merkle.valid_subtree(rs, re_)
        assert ls <= start <= le == rs <= end == re_
        assert max(le - ls, re_ - rs) <= merkle.bit_ceil(end - start)


def test_inclusion_proof_length_is_rfc_9162s() -> None:
    """§4.3: at most BIT_WIDTH(n − 1) hashes, and exactly PATH's length."""
    for start, end in subtrees():
        for index in range(start, end):
            assert len(TREE.inclusion_proof(start, end, index)) // 32 <= (end - start - 1).bit_length()


def test_a_huge_proof_is_rejected_in_logarithmic_work() -> None:
    """A 1 MiB proof for a 13-entry subtree stops at the first hash past the tree's height."""
    from qtls import crypto

    with crypto.count_ops() as ops:
        assert reason(lambda: ev(8, 13, 10, ref_mth(10, 11), b"\x00" * 2**20)) == "too-long"
        assert reason(lambda: vc(14, 8, 13, b"\x00" * 2**20, ref_mth(8, 13), ref_mth(0, 14))) == "too-long"
    assert ops[("openssl", "SHA-256", "merkle-digest")] < 70


def test_consistency_verification_is_counted() -> None:
    """Figure 8's proof, traced by hand through §4.4.3: the first hash seeds fr and sr; then d[13]
    extends sr (1), D[8:12) extends fr and sr (2), D[0:8) extends sr (1)."""
    from qtls import crypto

    proof = TREE.consistency_proof(8, 13, 14)
    with crypto.count_ops() as ops:
        vc(14, 8, 13, proof, ref_mth(8, 13), ref_mth(0, 14))
    assert ops[("openssl", "SHA-256", "merkle-digest")] == 4


def test_the_verifier_never_uses_the_builder() -> None:
    """D31: the relying-party functions are written from §4.3.2 and §4.4.3, not from Tree."""
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(merkle))
    functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}

    def names(node: ast.AST) -> set[str]:
        out = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
        return out | {n.attr for n in ast.walk(node) if isinstance(n, ast.Attribute)}

    # Everything the verifier reaches, following calls into module-level helpers.
    reached, todo = set(), ["evaluate_inclusion_proof", "verify_inclusion", "verify_consistency"]
    while todo:
        name = todo.pop()
        if name in reached:
            continue
        reached.add(name)
        found = names(functions[name])
        todo += [n for n in found if n in functions]
        assert not found & {"Tree", "_path", "_subproof", "_mth", "inclusion_proof", "consistency_proof"}, name
    assert {"node_hash", "valid_subtree", "_chunks"} <= reached


def test_merkle_error_reasons_are_a_closed_set() -> None:
    with pytest.raises(CodecUsageError):
        merkle.MerkleError("x", "no-such-reason")


def test_filler_block_next_to_a_real_entry_is_still_cheap() -> None:
    """The real entry sits just past a perfect filler block [0, 2^20): that block is one cached
    height, not 2^20 leaves rehashed."""
    from qtls import crypto

    size, entry = 2**20 + 1, _sha(b"last")
    with crypto.count_ops() as ops:
        tree = merkle.Tree(size, {2**20: entry}, FILLER)
        proof = tree.inclusion_proof(0, size, 2**20)
        root = tree.hash(0, size)
    assert ops[("openssl", "SHA-256", "merkle-digest")] < 100
    vi(0, size, 2**20, entry, proof, root)


def test_consistency_step_7_too_short() -> None:
    """§4.4.3 step 7: the subtree isn't a tree node (fn != sn), so the proof must supply its first hash."""
    assert reason(lambda: vc(4, 0, 3, b"", ref_mth(0, 3), ref_mth(0, 4))) == "too-short"
    v = next(v for v in LARGE_CONSISTENCY if v["Start"] != v["End"] and int(v["End"]) & (int(v["End"]) - 1)
             and v["End"] != v["TreeSize"])  # fmt: skip
    assert reason(lambda: vc(int(v["TreeSize"]), int(v["Start"]), int(v["End"]), b"", b64(v["SubtreeHash"]),
                             b64(v["TreeHash"]))) == "too-short"  # fmt: skip


def test_merkle_error_is_not_a_value_error() -> None:
    """Codec catch-alls (``except (DerError, ValueError, ...)`` in x509.py) must not swallow its reason."""
    assert not issubclass(merkle.MerkleError, ValueError)


def test_merkle_hash_uses_the_recorded_backend() -> None:
    """backend_info() records cryptography's OpenSSL; Merkle hashing runs there too, not on hashlib's."""
    import inspect

    from qtls import crypto

    assert "hashlib" not in inspect.getsource(crypto.merkle_sha256)
    assert crypto.merkle_sha256(b"abc") == bytes.fromhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    with pytest.raises(TypeError):
        merkle.leaf_hash("not bytes")  # type: ignore[arg-type]


def test_consistency_checks_the_subtree_hash_before_the_tree_hash() -> None:
    """§4.4.3 step 9 compares fr first: with both hashes wrong, the reason is the subtree's."""
    proof = TREE.consistency_proof(0, 3, 4)
    assert reason(lambda: vc(4, 0, 3, proof, flip(ref_mth(0, 3)), flip(ref_mth(0, 4)))) == "subtree-mismatch"
