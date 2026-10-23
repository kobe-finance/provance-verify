# Copyright 2026 Provance
# SPDX-License-Identifier: Apache-2.0
"""Verifying a Provance evidence bundle offline, layer by layer.

Nothing in the bundle is trusted until it is checked against what you hold
yourself: the key set you downloaded from Provance (``--keys``), the time-stamp
authority's certificate (``--tsa-cert``) and, optionally, the export archive
(``--export``). Layers, in order:

1. manifest      the manifest's signature (by key id, from your key set) and the
                 SHA-256 of every file, with no file missing or added;
2. records       every record's hash recomputed from its RFC 8785 form;
3. chains        each chain's record hashes give the root the anchor checkpoint
                 signed; every record sits at its position; every record links
                 to the one before it;
4. checkpoints   each checkpoint's signature, and each chain entry's inclusion
                 in the checkpoint's root;
5. timestamp     each checkpoint's RFC 3161 token over the statement's SHA-256;
6. consistency   earlier checkpoints' chain trees are prefixes of the anchor's;
7. seal          the seal's signature, its root from its leaves, and its record
                 on the chain;
8. lines         every exported line names a record in the bundle, or carries a
                 label; with --export, every line's bytes and the archive itself;
9. trace         every input that is a record or a stored version resolves, with
                 the hash it was cited with;
10. attestations every DSSE envelope's signature, and its Statement agrees with
                 the record it describes;
11. assurance    the signed assurance summary is bound to this seal and archive.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from cryptography import x509

from provance_verify import keys as keyset
from provance_verify import legacy, merkle, tsa
from provance_verify.jcs import JCSError, canonicalize

FORMAT = "provance-evidence-bundle"
FORMAT_VERSION = 1
GENERATION_PREDICATE = "https://provancelabs.org/attestations/generation/v1"
OUTPUT_PREDICATE = "https://provancelabs.org/attestations/output/v1"
# Bundles sealed before A-218 name the same predicates under the earlier domain
# (provance_verify.legacy): the URI is an identifier and is never fetched.
GENERATION_PREDICATES = frozenset({GENERATION_PREDICATE, legacy.GENERATION_PREDICATE})
OUTPUT_PREDICATES = frozenset({OUTPUT_PREDICATE, legacy.OUTPUT_PREDICATE})
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
_ENTRY_FIELDS = ("tenant_id", "chain_id", "head_seq", "head_hash", "tree_size", "tree_root")
_VERSION_KINDS = ("conversation_version", "gold_standard_version")

LAYERS = ("manifest", "records", "chains", "checkpoints", "timestamp", "consistency", "seal", "lines",
          "trace", "attestations", "assurance")


@dataclass
class Report:
    """What was checked, what failed, and a summary in words."""

    failures: dict[str, list[str]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    summary: list[str] = field(default_factory=list)
    checked: list[str] = field(default_factory=list)

    def fail(self, layer: str, message: str) -> None:
        self.failures.setdefault(layer, []).append(message)

    @property
    def valid(self) -> bool:
        return not self.failures

    def as_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "layers": {layer: {"ok": layer not in self.failures,
                                                        "failures": self.failures.get(layer, [])}
                                                for layer in self.checked},
                "warnings": self.warnings, "summary": self.summary}


class BundleError(ValueError):
    """The file is not a Provance evidence bundle this verifier can read."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _jcs_hash(value: Any) -> str | None:
    try:
        return _sha256(canonicalize(value))
    except JCSError:
        return None


def read_zip(content: bytes) -> dict[str, bytes]:
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            return {name: zf.read(name) for name in zf.namelist()}
    except zipfile.BadZipFile as exc:
        raise BundleError("not a ZIP file") from exc


def verify_bundle(
    content: bytes, *, trusted_keys: Mapping[str, keyset.TrustedKey],
    tsa_roots: Sequence[x509.Certificate] = (), export_archive: bytes | None = None,
    require_timestamp: bool = False,
) -> Report:
    """Verify an evidence bundle (see the module docstring)."""
    files = read_zip(content)
    report = Report()
    if "manifest.json" not in files:
        raise BundleError("no manifest.json: not a Provance evidence bundle")
    try:
        manifest = json.loads(files["manifest.json"])
    except json.JSONDecodeError as exc:
        raise BundleError("manifest.json is not JSON") from exc
    if manifest.get("format") != FORMAT or manifest.get("format_version") != FORMAT_VERSION:
        raise BundleError(f"unsupported bundle format {manifest.get('format')} {manifest.get('format_version')}")
    report.checked.extend(LAYERS)

    # 1. manifest
    body = {k: v for k, v in manifest.items() if k != "signature"}
    check = keyset.verify_block(body, manifest.get("signature"), trusted_keys, signed_at=manifest.get("created_at"))
    if not check.valid:
        report.fail("manifest", f"manifest.json signature: {check.reason} (key {check.key_id})")
    listed = {f["path"]: f["sha256"] for f in manifest.get("files") or []}
    for path in sorted(set(files) - {"manifest.json"} - set(listed)):
        report.fail("manifest", f"{path} is in the bundle but not in the signed manifest")
    for path, digest in sorted(listed.items()):
        if path not in files:
            report.fail("manifest", f"{path} is listed but missing")
        elif _sha256(files[path]) != digest:
            report.fail("manifest", f"{path} does not match its SHA-256 in the manifest")
    tenant_id = manifest.get("tenant_id")

    def load(path: str) -> Any:
        if path not in files:
            report.fail("manifest", f"{path} is missing")
            return None
        try:
            return json.loads(files[path])
        except json.JSONDecodeError:
            report.fail("manifest", f"{path} is not JSON")
            return None

    # 2. records and 3. chains
    records: dict[str, dict[str, Any]] = {}
    anchor_id = (manifest.get("checkpoints") or {}).get("anchor")
    anchor = load(f"checkpoints/{anchor_id}.json") or {}
    anchor_entries = {e.get("chain_id"): e for e in anchor.get("chains") or []}
    leaves_of: dict[str, list[bytes]] = {}
    for chain in manifest.get("chains") or []:
        chain_id = chain.get("chain_id")
        raw = files.get(chain.get("leaves_file") or "", b"")
        if len(raw) % 32:
            report.fail("chains", f"{chain_id}: the leaves file is not a list of 32-byte hashes")
            continue
        leaves = [raw[i:i + 32] for i in range(0, len(raw), 32)]
        leaves_of[chain_id] = leaves
        entry = anchor_entries.get(chain_id)
        tree_root = merkle.root(merkle.leaf_hash(h) for h in leaves).hex()
        if entry is None:
            report.fail("chains", f"{chain_id}: the anchor checkpoint does not hold this chain")
        elif len(leaves) != entry.get("tree_size") or tree_root != entry.get("tree_root") \
                or (leaves and leaves[-1].hex() != entry.get("head_hash")):
            report.fail("chains", f"{chain_id}: its record hashes do not give the root the checkpoint signed "
                                  "(the chain was changed after it was checkpointed)")
        for number, line in enumerate((files.get(chain.get("records_file") or "", b"")).decode().splitlines(), 1):
            try:
                rec = json.loads(line)
                record = rec["record"]
                position = int(rec["position"])
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                report.fail("records", f"{chain_id} line {number} is not a record")
                continue
            rid = str(rec.get("record_id"))
            records[rid] = {**rec, "chain_id": chain_id}
            if record.get("record_id") != rid or record.get("chain_id") != chain_id \
                    or record.get("tenant_id") != tenant_id or record.get("format_version") != 2:
                report.fail("records", f"record {rid} does not belong to {chain_id} of this tenant")
            if _jcs_hash(record) != rec.get("record_hash"):
                report.fail("records", f"record {rid} ({record.get('record_type')}): its content does not match "
                                       "its hash (it was changed)")
            if not 0 <= position < len(leaves) or leaves[position].hex() != rec.get("record_hash"):
                report.fail("chains", f"record {rid} is not on {chain_id} at position {position}")
            elif (position == 0 and record.get("prev_hash") is not None) or (
                    position > 0 and leaves[position - 1].hex() != record.get("prev_hash")):
                report.fail("chains", f"record {rid} does not link to the record before it")

    # 4. checkpoints and 5. timestamp
    checkpoint_ids = [anchor_id, *((manifest.get("checkpoints") or {}).get("earlier") or [])]
    checkpoints: dict[str, Any] = {}
    for cid in checkpoint_ids:
        cp = anchor if cid == anchor_id else load(f"checkpoints/{cid}.json")
        if not cp:
            report.fail("checkpoints", f"checkpoint {cid} is missing")
            continue
        checkpoints[cid] = cp
        statement = cp.get("statement") or {}
        check = keyset.verify_block(statement, cp.get("signature"), trusted_keys, signed_at=statement.get("created_at"))
        if not check.valid or statement.get("checkpoint_id") != cid:
            report.fail("checkpoints", f"checkpoint {cid}: signature {check.reason}")
        try:
            chains_root = bytes.fromhex(statement.get("chains_root") or "")
        except ValueError:
            chains_root = b""
        for entry in cp.get("chains") or []:
            leaf = merkle.leaf_hash(canonicalize({k: entry.get(k) for k in _ENTRY_FIELDS}))
            path = [bytes.fromhex(p) for p in entry.get("path") or []]
            if entry.get("tenant_id") != tenant_id or not merkle.verify_inclusion(
                    leaf, int(entry.get("leaf_index", -1)), int(statement.get("chain_count") or 0), path, chains_root):
                report.fail("checkpoints", f"checkpoint {cid}: {entry.get('chain_id')} is not in its signed root")
        stamp = cp.get("tsa") or {}
        digest = hashlib.sha256(canonicalize(statement)).digest()
        if stamp.get("status") != "timestamped" or not stamp.get("token"):
            message = f"checkpoint {cid} is signed but not timestamped ({stamp.get('status')}" + (
                f": {stamp.get('error')})" if stamp.get("error") else ")")
            (report.fail("timestamp", message) if require_timestamp else report.warnings.append(message))
            continue
        if not tsa_roots:
            message = f"checkpoint {cid}'s timestamp was not checked: give the TSA certificate with --tsa-cert"
            (report.fail("timestamp", message) if require_timestamp else report.warnings.append(message))
            continue
        try:
            token = tsa.verify_token(base64.b64decode(stamp["token"]), digest=digest, nonce=stamp.get("nonce"),
                                     trusted=tsa_roots)
        except tsa.TokenError as exc:
            report.fail("timestamp", f"checkpoint {cid}: {exc.reason}: {exc}")
            continue
        cp["_verified_time"] = token.gen_time.isoformat()
        cp["_tsa_subject"] = token.tsa_subject

    # 6. consistency
    for proof in (load("consistency.json") or {}).get("proofs") or []:
        chain_id = proof.get("chain_id")
        first, second = proof.get("from") or {}, proof.get("to") or {}
        earlier_entry = next((e for e in (checkpoints.get(first.get("checkpoint_id")) or {}).get("chains") or []
                              if e.get("chain_id") == chain_id), None)
        later_entry = next((e for e in (checkpoints.get(second.get("checkpoint_id")) or {}).get("chains") or []
                            if e.get("chain_id") == chain_id), None)
        ok = earlier_entry is not None and later_entry is not None \
            and (first.get("tree_size"), first.get("tree_root")) == (earlier_entry["tree_size"], earlier_entry["tree_root"]) \
            and (second.get("tree_size"), second.get("tree_root")) == (later_entry["tree_size"], later_entry["tree_root"]) \
            and merkle.verify_consistency(int(first["tree_size"]), int(second["tree_size"]),
                                          bytes.fromhex(first["tree_root"]), bytes.fromhex(second["tree_root"]),
                                          [bytes.fromhex(p) for p in proof.get("path") or []])
        leaves = leaves_of.get(chain_id) or []
        if ok and merkle.root(merkle.leaf_hash(h) for h in leaves[: int(first["tree_size"])]).hex() != first["tree_root"]:
            ok = False
        if not ok:
            report.fail("consistency", f"{chain_id}: checkpoint {first.get('checkpoint_id')} is not a prefix of "
                                       f"checkpoint {second.get('checkpoint_id')}")

    # 7. seal
    seal = load("seal.json") or {}
    statement = seal.get("statement") or {}
    check = keyset.verify_block(statement, seal.get("signature"), trusted_keys, signed_at=statement.get("sealed_at"))
    if not check.valid:
        report.fail("seal", f"the seal's signature: {check.reason}")
    if (statement.get("merkle_root"), statement.get("tree_size")) != (seal.get("merkle_root"), seal.get("tree_size")) \
            or (manifest.get("seal") or {}).get("merkle_root") != seal.get("merkle_root"):
        report.fail("seal", "the seal's root is not the one its statement signed")
    seal_record = records.get(str(seal.get("ledger_record_id")))
    if seal_record is None or seal_record["record"]["subject"].get("sha256") != seal.get("merkle_root") \
            or seal_record["record"]["outcome"].get("statement_sha256") != _jcs_hash(statement):
        report.fail("seal", "the seal is not recorded on the chain")
    lines: list[dict[str, Any]] = []
    if seal.get("leaf_kind") == "record_hash":
        leaf_hashes = [merkle.leaf_hash(bytes.fromhex(leaf["record_hash"])) for leaf in seal.get("leaves") or []]
        for leaf in seal.get("leaves") or []:
            if (records.get(leaf.get("record_id")) or {}).get("record_hash") != leaf.get("record_hash"):
                report.fail("seal", f"sealed record {leaf.get('record_id')} is not in the bundle with that hash")
    else:
        lines = (load("lines.json") or {}).get("lines") or []
        leaf_hashes = [bytes.fromhex(line["leaf_hash"]) for line in lines]
    if merkle.root(leaf_hashes).hex() != seal.get("merkle_root") or len(leaf_hashes) != seal.get("tree_size"):
        report.fail("seal", "the sealed leaves do not give the seal's root")

    # 8. lines (exports) and the export archive
    labelled: dict[str, int] = {}
    for line in lines:
        rid = line.get("record_id")
        if rid:
            record = (records.get(rid) or {}).get("record") or {}
            subject = record.get("subject") or {}
            if records.get(rid, {}).get("record_hash") != line.get("record_hash") or record.get("record_type") != "version" \
                    or (subject.get("id"), subject.get("version")) != (line.get("conversation_id"), line.get("version")):
                report.fail("lines", f"{line.get('file')} line {line.get('line')} names a record that is not its version's")
        elif line.get("label"):
            labelled[line["label"]] = labelled.get(line["label"], 0) + 1
        else:
            report.fail("lines", f"{line.get('file')} line {line.get('line')} names no record and carries no label")
    export = (manifest.get("subject") or {}).get("export")
    if export is not None:
        outputs = [r for r in records.values() if r["record"].get("record_type") == "export"]
        if not outputs or any(r["record"]["subject"].get("sha256") != export.get("archive_sha256") for r in outputs):
            report.fail("lines", "the export's records do not name its archive")
    if export_archive is not None:
        if export is None:
            report.fail("lines", "--export was given but this bundle is not an export's")
        else:
            _check_archive(export_archive, export, lines, records, report)

    # 9. trace
    unrecorded = {(u.get("kind"), str(u.get("id")), u.get("version")) for u in manifest.get("unrecorded_inputs") or []}
    versions = {(r["record"]["subject"].get("kind"), str(r["record"]["subject"].get("id")),
                 r["record"]["subject"].get("version")): r
                for r in records.values() if r["record"].get("record_type") == "version"}
    for rid, rec in records.items():
        for ref in rec["record"].get("inputs") or []:
            kind = str(ref.get("kind") or "")
            if kind.startswith("record:"):
                cited = records.get(str(ref.get("id")))
                if cited is None or cited.get("record_hash") != ref.get("sha256"):
                    report.fail("trace", f"record {rid} cites record {ref.get('id')}, which is not here with that hash")
            elif kind in _VERSION_KINDS:
                key = (kind, str(ref.get("id")), ref.get("version"))
                cited = versions.get(key)
                if cited is None and key not in unrecorded:
                    report.fail("trace", f"record {rid} cites {kind} {ref.get('id')} v{ref.get('version')}, "
                                         "whose record is not here")
                elif cited is not None and ref.get("sha256") and cited["record"]["subject"].get("sha256") != ref["sha256"]:
                    report.fail("trace", f"record {rid} cites {kind} {ref.get('id')} with another hash")

    # 10. attestations
    _check_attestations(files.get("attestations.dsse.jsonl", b""), records, seal, export, trusted_keys, report)

    # 11. assurance (exports)
    if export is not None:
        assurance = load("assurance.json") or {}
        a_statement = assurance.get("statement") or {}
        check = keyset.verify_block(a_statement, assurance.get("signature"), trusted_keys,
                                    signed_at=a_statement.get("generated_at"))
        if not check.valid or (a_statement.get("seal") or {}).get("merkle_root") != seal.get("merkle_root") \
                or a_statement.get("archive_sha256") != export.get("archive_sha256"):
            report.fail("assurance", "the assurance summary is not signed for this seal and archive")

    _summarise(report, manifest, records, lines, labelled, checkpoints, anchor_id, export_archive is not None)
    return report


def _parquet_rows(data: bytes, name: str, report: Report) -> list[bytes] | None:
    """Each row of a Parquet file as RFC 8785 JSON, or None (with a warning) when pyarrow is not installed.

    Reading Parquet needs pyarrow: ``pip install 'provance-verify[parquet]'``.
    Without it the rows' bytes in the archive are not compared (the seal and
    every row's record are still checked from lines.json), and the report
    says so.
    """
    try:
        import pyarrow.parquet as pq
    except ImportError:
        report.warnings.append(
            f"{name}: Parquet rows were not read from the archive; install provance-verify[parquet] to check them"
        )
        return None
    try:
        table = pq.read_table(io.BytesIO(data))
    except Exception as e:  # pyarrow raises several types for a file that is not Parquet
        report.fail("lines", f"{name} in the archive is not a readable Parquet file ({type(e).__name__})")
        return []
    return [canonicalize(row) for row in table.to_pylist()]


def _check_archive(archive: bytes, export: Mapping[str, Any], lines: Sequence[Mapping[str, Any]],
                   records: Mapping[str, Mapping[str, Any]], report: Report) -> None:
    if _sha256(archive) != export.get("archive_sha256"):
        report.fail("lines", "the export archive is not the one this bundle describes (SHA-256 differs)")
        return
    members = read_zip(archive)
    for f in export.get("files") or []:
        if _sha256(members.get(f["path"], b"")) != f["sha256"]:
            report.fail("lines", f"{f['path']} in the archive does not match its SHA-256")
    by_file = {}
    for name, data in members.items():
        split = data.split(b"\n")
        by_file[name] = split[:-1] if split and split[-1] == b"" else split
    tables: dict[str, list[bytes] | None] = {}
    for line in lines:
        if "row" in line:  # a Parquet row: its leaf is the row's RFC 8785 JSON, read back from the file
            name = str(line.get("file"))
            if name not in tables:
                tables[name] = _parquet_rows(members.get(name, b""), name, report)
            table = tables[name]
            if table is None:
                continue  # reported once: rows could not be read here
            number = int(line.get("row") or 0)
            raw = table[number - 1] if 0 < number <= len(table) else None
            if raw is None or merkle.leaf_hash(raw).hex() != line.get("leaf_hash") or _sha256(raw) != line.get("sha256"):
                report.fail("lines", f"{name} row {number} in the archive is not the sealed row")
            continue
        rows = by_file.get(line.get("file")) or []
        number = int(line.get("line") or 0)
        raw = rows[number - 1] if 0 < number <= len(rows) else None
        if raw is None or merkle.leaf_hash(raw).hex() != line.get("leaf_hash") or _sha256(raw) != line.get("sha256"):
            report.fail("lines", f"{line.get('file')} line {number} in the archive is not the sealed line")
    manifest_digest = _sha256(members.get("corpus_manifest.json", b""))
    for rec in records.values():
        if rec["record"].get("record_type") == "export":
            cited = [i for i in rec["record"].get("inputs") or [] if i.get("kind") == "export_manifest"]
            if cited and cited[0].get("sha256") != manifest_digest:
                report.fail("lines", "the archive's corpus_manifest.json is not the one the export record names")


def _pae(payload_type: str, payload: bytes) -> bytes:
    kind = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(payload), payload)


def _digest_of(ref: Mapping[str, Any]) -> dict[str, str]:
    if not ref.get("sha256"):
        return {}
    return {"hmacSha256": ref["sha256"]} if ref.get("keyed_by") else {"sha256": ref["sha256"]}


def _check_attestations(raw: bytes, records: Mapping[str, Mapping[str, Any]], seal: Mapping[str, Any],
                        export: Mapping[str, Any] | None, trusted_keys: Mapping[str, keyset.TrustedKey],
                        report: Report) -> None:
    described: set[str] = set()
    outputs = 0
    for number, line in enumerate(raw.decode().splitlines(), 1):
        try:
            envelope = json.loads(line)
            payload = base64.b64decode(envelope["payload"], validate=True)
            (signature,) = envelope["signatures"]
            sig = base64.b64decode(signature["sig"], validate=True)
            statement = json.loads(payload)
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            report.fail("attestations", f"attestation {number} cannot be read")
            continue
        check = keyset.verify_bytes(str(signature.get("keyid")), sig, _pae(envelope.get("payloadType", ""), payload),
                                    trusted_keys)
        if not check.valid or envelope.get("payloadType") != DSSE_PAYLOAD_TYPE or statement.get("_type") != STATEMENT_TYPE:
            report.fail("attestations", f"attestation {number}: signature {check.reason}")
            continue
        predicate = statement.get("predicate") or {}
        if statement.get("predicateType") in GENERATION_PREDICATES:
            about = predicate.get("record") or {}
            rec = records.get(str(about.get("record_id")))
            if rec is None or rec.get("record_hash") != about.get("record_hash"):
                report.fail("attestations", f"attestation {number} describes a record that is not here")
                continue
            record = rec["record"]
            subjects = {s.get("name"): s.get("digest") for s in statement.get("subject") or []}
            deps = [d.get("digest") or {} for d in (predicate.get("buildDefinition") or {}).get("resolvedDependencies") or []]
            if subjects.get(f"provance:record/{record['record_id']}") != {"sha256": rec["record_hash"]} \
                    or (_digest_of(record["subject"]) and _digest_of(record["subject"]) not in subjects.values()) \
                    or deps != [_digest_of(ref) for ref in record.get("inputs") or []] \
                    or predicate.get("modelCall") != record.get("model_call") \
                    or predicate.get("outcome") != record.get("outcome"):
                report.fail("attestations", f"attestation {number} does not agree with record {record['record_id']}")
            described.add(record["record_id"])
        elif statement.get("predicateType") in OUTPUT_PREDICATES:
            outputs += 1
            sealed = predicate.get("seal") or {}
            subjects = {s.get("name"): (s.get("digest") or {}).get("sha256") for s in statement.get("subject") or []}
            ok = sealed.get("merkle_root") == seal.get("merkle_root") \
                and sealed.get("statement_sha256") == _jcs_hash(seal.get("statement") or {})
            if export is not None:
                ok = ok and subjects.get(export.get("archive_filename")) == export.get("archive_sha256") and all(
                    subjects.get(f["path"]) == f["sha256"] for f in export.get("files") or [])
            if not ok:
                report.fail("attestations", f"attestation {number} does not describe this output and seal")
        else:
            report.fail("attestations", f"attestation {number} has an unknown predicate type")
    if set(records) - described:
        report.fail("attestations", f"{len(set(records) - described)} record(s) have no attestation")
    if outputs != 1:
        report.fail("attestations", "the output attestation is missing")


def _summarise(report: Report, manifest: Mapping[str, Any], records: Mapping[str, Mapping[str, Any]],
               lines: Sequence[Mapping[str, Any]], labelled: Mapping[str, int], checkpoints: Mapping[str, Any],
               anchor_id: str | None, archive_checked: bool) -> None:
    scope, scope_id = manifest.get("scope"), manifest.get("scope_id")
    if scope == "export":
        with_record = sum(1 for line in lines if line.get("record_id"))
        text = f"All {len(lines)} exported line(s) are covered by the signed seal"
        text += (" and match the export archive" if archive_checked else "") + "."
        if with_record != len(lines):
            text += " " + "; ".join(f"{n} line(s) are {label}" for label, n in sorted(labelled.items())) + "."
        report.summary.append(text)
    else:
        report.summary.append(f"The {scope} {scope_id} is covered by its signed seal "
                              f"({(manifest.get('seal') or {}).get('tree_size')} records).")
    times = sorted(r["record"].get("recorded_at") or "" for r in records.values())
    if times:
        report.summary.append(f"{len(records)} record(s) trace it back to its first inputs, recorded from "
                              f"{times[0][:10]} to {times[-1][:10]}.")
    anchor = checkpoints.get(anchor_id or "") or {}
    key_id = (anchor.get("signature") or {}).get("key_id")
    if anchor.get("_verified_time"):
        report.summary.append(f"Checkpoint #{(anchor.get('statement') or {}).get('sequence')} signed by key {key_id}, "
                              f"timestamped {anchor['_verified_time']} by {anchor.get('_tsa_subject')}.")
    elif anchor:
        report.summary.append(f"Checkpoint #{(anchor.get('statement') or {}).get('sequence')} signed by key {key_id}; "
                              "its timestamp was not verified.")
    report.summary.append(f"Signer: {manifest.get('signer')}.")
