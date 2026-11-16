"""Merkle Tree subtrees and their proofs (MTC -08 §4, RFC 9162 §2.1; specs.md D31).

Two sides, written separately on purpose:

* The **builder** (:class:`Tree`) is what a CA runs: subtree hashes,
  inclusion proofs and consistency proofs over entries it holds. Its inputs
  are local, so misuse is a :class:`CodecUsageError`.
* The **verifier** functions are what a relying party runs on untrusted
  input: :func:`evaluate_inclusion_proof`, :func:`verify_inclusion` and
  :func:`verify_consistency`. They follow the step lists of MTC -08 §4.3.2 and
  §4.4.3 line by line, never call the builder, and report every failure as
  :class:`MerkleError` (an ``Exception``, not a ``ValueError``, so codec
  catch-alls can't swallow its reason). Callers that face a peer (MTC
  certificate verification) turn that into an alert. Hash arguments are 32
  bytes by contract: the caller's framing checks that, and a wrong length is
  the caller's bug (``CodecUsageError``), not the peer's.

The hash is SHA-256 (specs.md §2, a qTLS choice), through :mod:`qtls.crypto` so
it's counted. Leaves are ``H(0x00 ‖ entry)`` and interior nodes
``H(0x01 ‖ left ‖ right)``. A proof is its hashes concatenated, which is how
an MTCProof carries ``inclusion_proof`` (MTC -08 §6.2).

Sizes are Python integers, so nothing here overflows; the 48-bit bound on
``start`` and ``end`` belongs to the MTCProof codec, not to this module.
"""

from __future__ import annotations

import bisect
from collections.abc import Iterator, Mapping, Sequence

from qtls import crypto
from qtls.alerts import CodecUsageError

HASH_SIZE = 32


REASONS = frozenset({
    "not-subtree", "index-range", "end-beyond-tree", "ragged", "too-long", "too-short",
    "empty-subtree", "subtree-mismatch", "root-mismatch",
})  # fmt: skip


class MerkleError(Exception):
    """An untrusted subtree or proof that doesn't verify. ``reason`` names the failed check."""

    def __init__(self, message: str, reason: str) -> None:
        if reason not in REASONS:
            raise CodecUsageError(f"unknown MerkleError reason {reason!r}")
        super().__init__(message)
        self.reason = reason


def _hash(data: bytes) -> bytes:
    return crypto.merkle_sha256(data)


def digest(data: bytes) -> bytes:
    """HASH(data): the log's hash over other inputs, such as subjectPublicKeyInfoHash (MTC -08 §5.2.1)."""
    return _hash(data)


def leaf_hash(entry: bytes) -> bytes:
    """MTH({entry}) = HASH(0x00 ‖ entry) (RFC 9162 §2.1.1)."""
    return _hash(b"\x00" + entry)


def node_hash(left: bytes, right: bytes) -> bytes:
    """HASH(0x01 ‖ left ‖ right) (RFC 9162 §2.1.1)."""
    return _hash(b"\x01" + left + right)


def empty_hash() -> bytes:
    """MTH({}) = HASH(), the hash of the empty string."""
    return _hash(b"")


def bit_ceil(n: int) -> int:
    """The smallest power of two that is at least ``n`` (1 for 0 and 1)."""
    return 1 if n <= 1 else 1 << (n - 1).bit_length()


def valid_subtree(start: int, end: int) -> bool:
    """MTC -08 §4.1: ``0 <= start <= end`` and ``start`` is a multiple of BIT_CEIL(end − start)."""
    return 0 <= start <= end and start % bit_ceil(end - start) == 0


def find_subtrees(start: int, end: int) -> tuple[tuple[int, int], tuple[int, int]]:
    """The two subtrees that efficiently cover ``[start, end)`` (MTC -08 §4.5.1)."""
    if not 0 <= start <= end:
        raise CodecUsageError(f"[{start}, {end}) isn't an interval")
    if end - start <= 1:
        return (start, end), (end, end)
    last = end - 1
    split = (start ^ last).bit_length() - 1  # where start's and last's paths diverge
    mask = (1 << split) - 1
    mid = last & ~mask
    left_split = (~start & mask).bit_length()
    left_start = start & ~((1 << left_split) - 1)
    return (left_start, mid), (mid, end)


def _largest_power_of_two_below(n: int) -> int:
    """k with k < n <= 2k, for n > 1 (RFC 9162 §2.1.1)."""
    return 1 << ((n - 1).bit_length() - 1)


def _chunks(proof: bytes) -> Iterator[bytes]:
    for i in range(0, len(proof), HASH_SIZE):
        yield proof[i : i + HASH_SIZE]


def _check_hash(value: bytes, what: str) -> None:
    if len(value) != HASH_SIZE:
        raise CodecUsageError(f"{what} must be {HASH_SIZE} bytes")


# --------------------------------------------------------------------------- #
# Builder (a CA's view of its own log)
# --------------------------------------------------------------------------- #


class Tree:
    """MTH over a log of ``size`` entries, with subtree hashes and proofs (MTC -08 §4).

    The log is **sparse**: ``leaves`` maps the indices whose leaf hashes are
    given, and every other index holds ``filler`` (an MTC log pads with
    ``null_entry``, which MTC -08 §5.2.1 allows at any index). A perfect subtree
    of filler is hashed once per height, so cost grows with the given leaves
    and log₂(size), not with size: a landmark subtree of 2^22+ entries, which
    D14's 23-hash proofs need, costs a few hundred hashes.
    """

    def __init__(self, size: int, leaves: Mapping[int, bytes], filler: bytes | None = None) -> None:
        if size < 0:
            raise CodecUsageError("a tree has a non-negative size")
        for index, leaf in leaves.items():
            if not 0 <= index < size:
                raise CodecUsageError(f"leaf {index} is outside a tree of {size}")
            _check_hash(leaf, "a leaf hash")
        if filler is None:
            if len(leaves) != size:
                raise CodecUsageError("a tree with gaps needs a filler leaf hash")
        else:
            _check_hash(filler, "the filler leaf hash")
        self._size = size
        self._leaves = dict(leaves)
        self._indices = sorted(leaves)
        self._filler = filler
        self._filler_heights: list[bytes] = [filler] if filler is not None else []
        self._memo: dict[tuple[int, int], bytes] = {}

    @classmethod
    def from_entries(cls, entries: Sequence[bytes]) -> Tree:
        """A dense tree over ``entries`` (each hashed as a leaf)."""
        return cls(len(entries), {i: leaf_hash(e) for i, e in enumerate(entries)})

    def __len__(self) -> int:
        return self._size

    def hash(self, start: int, end: int) -> bytes:
        """MTH(D[start:end]). Any interval of the tree; a subtree if [start, end) is valid."""
        if not 0 <= start <= end <= self._size:
            raise CodecUsageError(f"[{start}, {end}) isn't inside a tree of {self._size}")
        return self._mth(start, end)

    def _all_filler(self, start: int, end: int) -> bool:
        i = bisect.bisect_left(self._indices, start)
        return i == len(self._indices) or self._indices[i] >= end

    def _perfect_filler(self, height: int) -> bytes:
        while len(self._filler_heights) <= height:
            below = self._filler_heights[-1]
            self._filler_heights.append(node_hash(below, below))
        return self._filler_heights[height]

    def _mth(self, start: int, end: int) -> bytes:
        n = end - start
        if n == 0:
            return empty_hash()
        if n == 1:
            leaf = self._leaves.get(start)
            if leaf is None:
                assert self._filler is not None
                return self._filler
            return leaf
        if n & (n - 1) == 0 and self._filler is not None and self._all_filler(start, end):
            return self._perfect_filler(n.bit_length() - 1)
        key = (start, end)
        if key not in self._memo:
            k = _largest_power_of_two_below(n)
            self._memo[key] = node_hash(self._mth(start, start + k), self._mth(start + k, end))
        return self._memo[key]

    def inclusion_proof(self, start: int, end: int, index: int) -> bytes:
        """The subtree inclusion proof for entry ``index`` of [start, end) (MTC -08 §4.3)."""
        if not valid_subtree(start, end) or end > self._size:
            raise CodecUsageError(f"[{start}, {end}) isn't a subtree of a tree of {self._size}")
        if not start <= index < end:
            raise CodecUsageError(f"entry {index} isn't in [{start}, {end})")
        return b"".join(self._path(index - start, start, end))

    def _path(self, m: int, lo: int, hi: int) -> list[bytes]:
        """RFC 9162 §2.1.3.1 PATH(m, D[lo:hi])."""
        n = hi - lo
        if n == 1:
            return []
        k = _largest_power_of_two_below(n)
        if m < k:
            return [*self._path(m, lo, lo + k), self._mth(lo + k, hi)]
        return [*self._path(m - k, lo + k, hi), self._mth(lo, lo + k)]

    def consistency_proof(self, start: int, end: int, n: int) -> bytes:
        """SUBTREE_PROOF(start, end, D_n) (MTC -08 §4.4.1)."""
        if not valid_subtree(start, end) or not end <= n <= self._size:
            raise CodecUsageError(f"[{start}, {end}) isn't a subtree of a tree of {n}")
        if start == end:
            return b""
        return b"".join(self._subproof(start, end, 0, n, True))

    def _subproof(self, start: int, end: int, lo: int, hi: int, omit: bool) -> list[bytes]:
        """SUBTREE_SUBPROOF(start, end, D[lo:hi], omit); start and end are relative to lo."""
        n = hi - lo
        if start == 0 and end == n:
            return [] if omit else [self._mth(lo, hi)]
        k = _largest_power_of_two_below(n)
        if end <= k:
            return [*self._subproof(start, end, lo, lo + k, omit), self._mth(lo + k, hi)]
        if k <= start:
            return [*self._subproof(start - k, end - k, lo + k, hi, omit), self._mth(lo, lo + k)]
        # start < k < end, so start == 0
        return [*self._subproof(0, end - k, lo + k, hi, False), self._mth(lo, lo + k)]


# --------------------------------------------------------------------------- #
# Verifier (a relying party; every input is untrusted)
# --------------------------------------------------------------------------- #


def evaluate_inclusion_proof(*, start: int, end: int, index: int, entry_hash: bytes, proof: bytes) -> bytes:
    """The subtree hash ``proof`` implies for ``entry_hash`` at ``index`` (MTC -08 §4.3.2)."""
    _check_hash(entry_hash, "entry_hash")
    # 1.
    if not valid_subtree(start, end):
        raise MerkleError(f"[{start}, {end}) isn't a valid subtree", "not-subtree")
    if not start <= index < end:  # the only thing tying the proof to this index (and the serial)
        raise MerkleError(f"entry {index} isn't in [{start}, {end})", "index-range")
    if len(proof) % HASH_SIZE:
        raise MerkleError("inclusion proof isn't a whole number of hashes", "ragged")
    # 2.–3.
    fn, sn = index - start, end - start - 1
    r = entry_hash
    # 4.
    for p in _chunks(proof):
        if sn == 0:
            raise MerkleError("inclusion proof is too long", "too-long")
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            while not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    # 5.
    if sn != 0:
        raise MerkleError("inclusion proof is too short", "too-short")
    # 6.
    return r


def verify_inclusion(
    *, start: int, end: int, index: int, entry_hash: bytes, proof: bytes, subtree_hash: bytes
) -> None:
    """MTC -08 §4.3.3: the entry is in the subtree with ``subtree_hash``, or :class:`MerkleError`."""
    _check_hash(subtree_hash, "subtree_hash")
    evaluated = evaluate_inclusion_proof(start=start, end=end, index=index, entry_hash=entry_hash, proof=proof)
    if evaluated != subtree_hash:
        raise MerkleError("inclusion proof doesn't lead to the subtree hash", "subtree-mismatch")


def verify_consistency(
    *, n: int, start: int, end: int, proof: bytes, subtree_hash: bytes, root_hash: bytes
) -> None:
    """MTC -08 §4.4.3: [start, end) with ``subtree_hash`` is consistent with the tree of
    ``n`` entries with ``root_hash``, or :class:`MerkleError`."""
    _check_hash(subtree_hash, "subtree_hash")
    _check_hash(root_hash, "root_hash")
    # 1.
    if not valid_subtree(start, end):
        raise MerkleError(f"[{start}, {end}) isn't a valid subtree", "not-subtree")
    if end > n:
        raise MerkleError(f"[{start}, {end}) ends beyond a tree of {n}", "end-beyond-tree")
    if len(proof) % HASH_SIZE:
        raise MerkleError("consistency proof isn't a whole number of hashes", "ragged")
    # 2.
    if start == end:
        if proof or subtree_hash != empty_hash():
            raise MerkleError("an empty subtree has an empty proof and the empty hash", "empty-subtree")
        return
    # 3.
    fn, sn, tn = start, end - 1, n - 1
    # 4.–5.
    if sn == tn:
        while fn != sn:
            fn, sn, tn = fn >> 1, sn >> 1, tn >> 1
    else:
        while fn != sn and sn & 1:
            fn, sn, tn = fn >> 1, sn >> 1, tn >> 1
    hashes = _chunks(proof)  # lazy: an over-long proof stops at step 8.1, not after a copy
    # 6.–7.
    if fn == sn:
        fr = sr = subtree_hash
    else:
        first = next(hashes, None)
        if first is None:
            raise MerkleError("consistency proof is too short", "too-short")
        fr = sr = first
    # 8.
    for c in hashes:
        if tn == 0:
            raise MerkleError("consistency proof is too long", "too-long")
        if sn & 1 or sn == tn:
            if fn < sn:
                fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            while not sn & 1:
                fn, sn, tn = fn >> 1, sn >> 1, tn >> 1
        else:
            sr = node_hash(sr, c)
        fn, sn, tn = fn >> 1, sn >> 1, tn >> 1
    # 9.
    if tn != 0:
        raise MerkleError("consistency proof is too short", "too-short")
    if fr != subtree_hash:
        raise MerkleError("consistency proof doesn't lead to the subtree hash", "subtree-mismatch")
    if sr != root_hash:
        raise MerkleError("consistency proof doesn't lead to the tree hash", "root-mismatch")
