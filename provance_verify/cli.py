# Copyright 2026 Provance
# SPDX-License-Identifier: Apache-2.0
"""``provance-verify``: check a Provance evidence bundle (or a seal) offline.

    provance-verify BUNDLE.zip --keys provance-keys.json --tsa-cert tsa.pem [--export EXPORT.zip]
    provance-verify --seal seal.json --keys provance-keys.json OUTPUT.jsonl [MORE.jsonl ...]

Exit status: 0 verified, 1 a check failed, 2 the input could not be read.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from provance_verify import __version__
from provance_verify import keys as keyset
from provance_verify import tsa
from provance_verify.bundle import LAYERS, BundleError, Report, verify_bundle
from provance_verify.seal import verify_seal


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="provance-verify",
        description="Verify a Provance evidence bundle, or a sealed output, without contacting Provance.",
    )
    parser.add_argument("paths", nargs="+", help="the evidence bundle (ZIP); with --seal, the output's JSONL file(s)")
    parser.add_argument("--keys", required=True,
                        help="the key set you downloaded from GET /v1/engine/provenance/public-key (never the bundle's)")
    parser.add_argument("--tsa-cert", action="append", default=[],
                        help="PEM certificate of the timestamp authority you trust (repeatable)")
    parser.add_argument("--export", help="the export archive (ZIP) the bundle describes")
    parser.add_argument("--seal", help="verify this seal (JSON) against the given JSONL file(s) instead of a bundle")
    parser.add_argument("--require-timestamp", action="store_true",
                        help="fail when a checkpoint is not timestamped or its timestamp cannot be checked")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    parser.add_argument("--version", action="version", version=f"provance-verify {__version__}")
    return parser


def _print(report: Report, as_json: bool) -> None:
    if as_json:
        print(json.dumps(report.as_dict(), indent=2))
        return
    print("VERIFIED" if report.valid else "NOT VERIFIED")
    for line in report.summary:
        print(f"  {line}")
    for layer in [layer for layer in LAYERS if layer in report.checked] + [
            layer for layer in report.checked if layer not in LAYERS]:
        failures = report.failures.get(layer)
        print(f"  [{'ok' if not failures else 'FAILED'}] {layer}")
        for failure in failures or []:
            print(f"      - {failure}")
    for warning in report.warnings:
        print(f"  warning: {warning}")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        trusted = keyset.load_key_set(args.keys)
        if args.seal:
            seal = json.loads(Path(args.seal).read_text())
            report = verify_seal(seal.get("seal", seal), [Path(p).read_bytes() for p in args.paths],
                                 trusted_keys=trusted)
        else:
            if len(args.paths) != 1:
                print("provance-verify: give one evidence bundle", file=sys.stderr)
                return 2
            report = verify_bundle(
                Path(args.paths[0]).read_bytes(), trusted_keys=trusted,
                tsa_roots=tsa.load_certificates(args.tsa_cert),
                export_archive=Path(args.export).read_bytes() if args.export else None,
                require_timestamp=args.require_timestamp,
            )
    except (OSError, ValueError, keyset.KeySetError, BundleError) as exc:
        print(f"provance-verify: {exc}", file=sys.stderr)
        return 2
    _print(report, args.json)
    return 0 if report.valid else 1
