# Copyright 2026 Provance
# SPDX-License-Identifier: Apache-2.0
"""RFC 9162 Merkle trees: roots, inclusion and consistency proofs (SHA-256).

leaf hash = SHA-256(0x00 || leaf); node hash = SHA-256(0x01 || left || right).
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence

EMPTY_ROOT = hashlib.sha256(b"").digest()


def leaf_hash(leaf: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + leaf).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def root(leaf_hashes: Iterable[bytes]) -> bytes:
    """The tree hash of leaves already hashed with :func:`leaf_hash` (one pass, a stack of subtrees)."""
    stack: list[tuple[int, bytes]] = []
    for h in leaf_hashes:
        size, value = 1, h
        while stack and stack[-1][0] == size:
            _, left = stack.pop()
            size, value = size * 2, node_hash(left, value)
        stack.append((size, value))
    if not stack:
        return EMPTY_ROOT
    value = stack[-1][1]
    for _, left in reversed(stack[:-1]):
        value = node_hash(left, value)
    return value


def verify_inclusion(leaf: bytes, index: int, tree_size: int, proof: Sequence[bytes], expected_root: bytes) -> bool:
    """RFC 9162 §2.1.3.2."""
    if not 0 <= index < tree_size:
        return False
    fn, sn, r = index, tree_size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == expected_root


def verify_consistency(first: int, second: int, first_root: bytes, second_root: bytes, proof: Sequence[bytes]) -> bool:
    """RFC 9162 §2.1.4.2."""
    if not 0 < first <= second:
        return False
    if first == second:
        return not proof and first_root == second_root
    path = list(proof)
    if first & (first - 1) == 0:
        path.insert(0, first_root)
    if not path:
        return False
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == first_root and sr == second_root and sn == 0
