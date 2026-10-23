# Copyright 2026 Provance
# SPDX-License-Identifier: Apache-2.0
"""Verifying a seal on its own: a /convert or /dispatch output, or an export's lines.

The seal (from the convert or dispatch response, or the dispatch manifest)
signs the RFC 9162 root over every line of the output, in order; the leaf is
a line's bytes without its newline. Give the files in the order they were
delivered (dispatch: the order of ``locations``).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from provance_verify import keys as keyset
from provance_verify import merkle
from provance_verify.bundle import Report


def jsonl_lines(body: bytes) -> list[bytes]:
    lines = body.split(b"\n")
    return lines[:-1] if lines and lines[-1] == b"" else lines


def verify_seal(seal: Mapping[str, Any], files: Sequence[bytes], *,
                trusted_keys: Mapping[str, keyset.TrustedKey]) -> Report:
    """Check a seal's signature and that ``files`` (in order) are exactly the sealed lines."""
    report = Report(checked=["seal", "lines"])
    statement = seal.get("statement") or {}
    check = keyset.verify_block(statement, seal.get("signature"), trusted_keys, signed_at=statement.get("sealed_at"))
    if not check.valid:
        report.fail("seal", f"the seal's signature: {check.reason} (key {check.key_id})")
    if (statement.get("merkle_root"), statement.get("tree_size")) != (seal.get("merkle_root"), seal.get("tree_size")):
        report.fail("seal", "the seal's root is not the one its statement signed")
    leaves = [merkle.leaf_hash(line) for body in files for line in jsonl_lines(body)]
    if merkle.root(leaves).hex() != statement.get("merkle_root") or len(leaves) != statement.get("tree_size"):
        report.fail("lines", f"the {len(leaves)} line(s) given are not the {statement.get('tree_size')} sealed line(s)")
    if report.valid:
        report.summary.append(f"All {len(leaves)} line(s) are the ones sealed by key {check.key_id} "
                              f"({statement.get('scope')} {statement.get('scope_id')}, sealed {statement.get('sealed_at')}).")
    return report
