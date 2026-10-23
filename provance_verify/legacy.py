# Copyright 2026 Provance
# SPDX-License-Identifier: Apache-2.0
"""Identifiers in evidence sealed before Provance moved to provancelabs.org (A-218).

Evidence made before 2026-10-22 names its predicate and statement types under the
earlier domain, provancelabs.com. Sealed evidence is append-only and is never
rewritten, so those bundles keep these URIs. A type or predicate URI is an
identifier, not an address: nothing is fetched from it, and the dropped domain is
never contacted. The verifier accepts these identifiers alongside the current
ones; everything else about the bundle is checked exactly as before.
"""

from __future__ import annotations

GENERATION_PREDICATE = "https://provancelabs.com/attestations/generation/v1"
OUTPUT_PREDICATE = "https://provancelabs.com/attestations/output/v1"
