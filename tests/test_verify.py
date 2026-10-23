"""provance-verify against real bundles made by provance-api's tests (tests/fixtures), and a
tampered copy for every layer.

Two kinds of tampering:

- by an outsider (no signing key): any change breaks the manifest's file
  hashes or a signature;
- by an insider who holds Provance's signing key and re-signs what it can
  (``Insider``): the records, chain, seal and attestation checks still catch
  inconsistent edits, and a consistent rewrite of a chain after its
  checkpoint is caught by the RFC 3161 timestamp, which no key can re-make
  (PROV-001).

The fixtures are regenerated with PROVANCE_WRITE_BUNDLE_FIXTURES=<dir> on
provance-api's tests/synthetic/test_evidence_bundle.py and
tests/formatter/test_output_seals.py (export-formats: an export in Provance
JSONL, CSV, Markdown, Bedrock and OpenAI formats; export-parquet: the same
with a Parquet file, whose leaves are its rows).
"""

from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from provance_verify import cli, legacy, merkle, tsa
from provance_verify import keys as keyset
from provance_verify.bundle import GENERATION_PREDICATE, OUTPUT_PREDICATE, BundleError, verify_bundle
from provance_verify.jcs import canonicalize
from provance_verify.seal import verify_seal

FIXTURES = Path(__file__).parent / "fixtures"


def _set(name: str) -> dict[str, Path]:
    return {p.name: p for p in (FIXTURES / name).iterdir()}


def _files(bundle: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(bundle)) as zf:
        return {n: zf.read(n) for n in zf.namelist()}


def _zip(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        for name, data in sorted(files.items()):
            zf.writestr(name, data)
    return buffer.getvalue()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class World:
    """One fixture set: the bundle's files, the trusted keys and the TSA root."""

    def __init__(self, name: str) -> None:
        paths = _set(name)
        self.files = _files(paths["bundle.zip"].read_bytes())
        self.keys_path = paths["provance-keys.json"]
        self.trusted = keyset.load_key_set(self.keys_path)
        self.tsa = tsa.load_certificates([str(paths["tsa.pem"])]) if "tsa.pem" in paths else []
        self.other_tsa = tsa.load_certificates([str(paths["other-tsa.pem"])]) if "other-tsa.pem" in paths else []
        self.archive = paths["export.zip"].read_bytes() if "export.zip" in paths else None
        self.paths = paths

    def json(self, name: str):
        return json.loads(self.files[name])

    def put(self, name: str, value) -> None:
        self.files[name] = (json.dumps(value, indent=2) + "\n").encode() if not isinstance(value, bytes) else value

    def verify(self, *, trusted=None, tsa_roots=None, archive=..., require_timestamp=False):
        return verify_bundle(
            _zip(self.files), trusted_keys=trusted or self.trusted,
            tsa_roots=self.tsa if tsa_roots is None else tsa_roots,
            export_archive=self.archive if archive is ... else archive, require_timestamp=require_timestamp,
        )

    def records_file(self) -> str:
        return next(n for n in self.files if n.startswith("records/"))

    def leaves_file(self) -> str:
        return next(n for n in self.files if n.startswith("chains/"))

    def records(self) -> list[dict]:
        return [json.loads(x) for x in self.files[self.records_file()].decode().splitlines()]

    def put_records(self, records: list[dict]) -> None:
        self.files[self.records_file()] = ("\n".join(json.dumps(r) for r in records) + "\n").encode()


class Insider:
    """Someone who holds a signing key Provance's key set trusts, and re-signs what they change."""

    def __init__(self, world: World) -> None:
        self.private = Ed25519PrivateKey.generate()
        raw = self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.key_id = keyset.key_id_for(raw)
        # The key set trusts the insider's key as much as Provance's own.
        self.trusted = {**world.trusted, self.key_id: keyset.TrustedKey(
            self.key_id, self.private.public_key(), "current", None)}
        self.world = world

    def sign(self, data: dict) -> dict:
        return {"algorithm": "Ed25519", "key_id": self.key_id, "canonicalization": "RFC 8785 (JCS)",
                "value": base64.b64encode(self.private.sign(canonicalize(data))).decode()}

    def envelope(self, statement: dict) -> dict:
        payload = canonicalize(statement)
        kind = b"application/vnd.in-toto+json"
        pae = b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(payload), payload)
        return {"payloadType": kind.decode(), "payload": base64.b64encode(payload).decode(),
                "signatures": [{"keyid": self.key_id, "sig": base64.b64encode(self.private.sign(pae)).decode()}]}

    def resign_manifest(self) -> None:
        w = self.world
        manifest = w.json("manifest.json")
        manifest.pop("signature")
        manifest["files"] = [{"path": n, "sha256": _sha(d), "size_bytes": len(d)}
                             for n, d in sorted(w.files.items()) if n != "manifest.json"]
        manifest["signature"] = self.sign(manifest)
        w.put("manifest.json", manifest)

    def verify(self, **kwargs):
        return self.world.verify(trusted=self.trusted, **kwargs)


def _write(path: Path, value) -> Path:
    path.write_text(json.dumps(value))
    return path


@pytest.fixture(params=["export", "export-consistency", "export-labelled", "export-formats", "export-parquet", "batch"])
def any_bundle(request) -> World:
    return World(request.param)


@pytest.fixture
def export() -> World:
    return World("export")


def _failed(report) -> set[str]:
    return set(report.failures)


# ---------------------------------------------------------------------------
# The good path
# ---------------------------------------------------------------------------


def test_every_bundle_made_by_the_api_verifies(any_bundle):
    report = any_bundle.verify(require_timestamp=True)
    assert report.valid, report.failures
    assert not report.warnings
    assert any("timestamped" in line for line in report.summary)


def test_a_labelled_line_is_reported_not_failed():
    report = World("export-labelled").verify()
    assert report.valid
    assert "1 line(s) are recorded before provenance tracking" in report.summary[0]


def test_an_export_in_several_formats_verifies_every_line_of_every_file():
    """CSV and Markdown records span several lines; each line is sealed and names its version (2026-10-21)."""
    world = World("export-formats")
    report = world.verify(require_timestamp=True)
    assert report.valid, report.failures
    assert report.summary[0].startswith("All 23 exported line(s) are covered by the signed seal")


def _verify_with_archive(world: World, archive: bytes):
    return verify_bundle(_zip(world.files), trusted_keys=world.trusted, tsa_roots=world.tsa, export_archive=archive)


def test_an_export_with_parquet_verifies_its_rows_read_back_from_the_archive():
    """A Parquet file's leaves are its rows in RFC 8785 JSON (2026-10-22)."""
    world = World("export-parquet")
    report = world.verify(require_timestamp=True)
    assert report.valid, report.failures
    assert not report.warnings
    lines = json.loads(world.files["lines.json"])["lines"]
    assert [x["row"] for x in lines if x["file"] == "ds_parquet.parquet"] == [1]


def test_a_changed_parquet_row_is_caught():
    import pyarrow as pa
    import pyarrow.parquet as pq

    world = World("export-parquet")
    members = _files(world.archive)
    table = pq.read_table(io.BytesIO(members["ds_parquet.parquet"]))
    rows = table.to_pylist()
    rows[0]["category"] = "changed"
    buffer = io.BytesIO()
    pq.write_table(pa.Table.from_pylist(rows, schema=table.schema), buffer)
    members["ds_parquet.parquet"] = buffer.getvalue()
    tampered = _zip(members)
    # The archive's own hash already differs; compare the rows as if it did not.
    from provance_verify.bundle import Report, _check_archive

    report = Report()
    lines = json.loads(world.files["lines.json"])["lines"]
    _check_archive(tampered, {"archive_sha256": _sha(tampered), "files": []}, lines, {}, report)
    assert report.failures["lines"] == ["ds_parquet.parquet row 1 in the archive is not the sealed row"]
    assert not _verify_with_archive(world, tampered).valid


def test_without_pyarrow_parquet_rows_are_reported_not_passed_silently(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def no_pyarrow(name, *args, **kwargs):
        if name.startswith("pyarrow"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_pyarrow)
    world = World("export-parquet")
    report = _verify_with_archive(world, world.archive)
    assert report.valid
    assert any("provance-verify[parquet]" in w for w in report.warnings)


def test_the_cli_answers_0_1_and_2(export, tmp_path, capsys):
    p = export.paths
    args = [str(p["bundle.zip"]), "--keys", str(p["provance-keys.json"]), "--tsa-cert", str(p["tsa.pem"]),
            "--export", str(p["export.zip"])]
    assert cli.main(args) == 0
    assert capsys.readouterr().out.startswith("VERIFIED")
    assert cli.main([*args[:-2], "--export", str(_write(tmp_path / "x.zip", {}))]) == 1  # another archive
    assert cli.main([str(p["bundle.zip"]), "--keys", str(_write(tmp_path / "k.json", {"keys": []}))]) == 2


def test_the_cli_prints_json(export, capsys):
    p = export.paths
    assert cli.main([str(p["bundle.zip"]), "--keys", str(p["provance-keys.json"]), "--tsa-cert", str(p["tsa.pem"]),
                     "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["valid"] is True and out["layers"]["timestamp"]["ok"] is True


# ---------------------------------------------------------------------------
# Keys: only the key set you hold is trusted
# ---------------------------------------------------------------------------


def test_a_bundle_signed_with_its_own_embedded_key_is_not_trusted(export):
    insider = Insider(export)
    # A forger replaces keys.json with their own key and re-signs everything.
    forged = json.loads(export.files["keys.json"])
    forged["keys"] = [{"key_id": insider.key_id, "public_key": base64.b64encode(
        insider.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode(), "status": "current"}]
    export.put("keys.json", forged)
    insider.resign_manifest()
    report = export.verify()  # your key set, not the bundle's
    assert "manifest" in _failed(report)
    assert any("unknown_key" in f for f in report.failures["manifest"])


def test_a_key_retired_before_the_bundle_was_made_does_not_verify_it(export, tmp_path):
    published = json.loads(export.keys_path.read_text())
    for key in published["keys"]:
        key["status"], key["retired_at"] = "retired", "2020-01-01T00:00:00+00:00"
    report = export.verify(trusted=keyset.load_key_set(_write(tmp_path / "retired.json", published)))
    assert any("key_retired" in f for f in report.failures["manifest"])


def test_a_key_set_whose_id_does_not_match_its_key_is_refused(export, tmp_path):
    published = json.loads(export.keys_path.read_text())
    published["keys"][0]["key_id"] = "0" * 16
    with pytest.raises(keyset.KeySetError):
        keyset.load_key_set(_write(tmp_path / "bad.json", published))


# ---------------------------------------------------------------------------
# One tampered layer at a time
# ---------------------------------------------------------------------------


def test_manifest_a_changed_file_or_an_added_one(export):
    export.files["prov.json"] += b" "
    assert _failed(export.verify()) == {"manifest"}
    world = World("export")
    world.files["extra.txt"] = b"x"
    assert _failed(world.verify()) == {"manifest"}
    world = World("export")
    manifest = world.json("manifest.json")
    manifest["signer"] = "Provance"
    world.put("manifest.json", manifest)
    assert any("bad_signature" in f for f in world.verify().failures["manifest"])


def test_records_a_changed_record(export):
    insider = Insider(export)
    records = export.records()
    target = next(r for r in records if r["record"]["record_type"] == "qa")
    target["record"]["outcome"]["verdict"] = "FLAG" if target["record"]["outcome"]["verdict"] != "FLAG" else "PASS"
    export.put_records(records)
    insider.resign_manifest()
    assert "records" in _failed(insider.verify())


def test_chains_a_record_rehashed_but_not_on_its_chain(export):
    insider = Insider(export)
    records = export.records()
    target = next(r for r in records if r["record"]["record_type"] == "qa")
    target["record"]["outcome"]["score"] = 1
    target["record_hash"] = _sha(canonicalize(target["record"]))
    export.put_records(records)
    insider.resign_manifest()
    failed = _failed(insider.verify())
    assert "chains" in failed and "records" not in failed


def test_chains_a_changed_leaf(export):
    insider = Insider(export)
    name = export.leaves_file()
    leaves = bytearray(export.files[name])
    leaves[5] ^= 0x01
    export.files[name] = bytes(leaves)
    insider.resign_manifest()
    assert "chains" in _failed(insider.verify())


def _rewrite_last_record(world: World, insider: Insider) -> None:
    """A consistent rewrite of the chain's last record (the export record), every hash recomputed
    and re-signed by the insider: records, leaves, the checkpoint entry and statement, the
    attestations and the manifest. Only the RFC 3161 token cannot be re-made."""
    records = world.records()
    target = max(records, key=lambda r: r["position"])
    old_hash = target["record_hash"]
    target["record"]["outcome"]["archive_size_bytes"] += 1
    target["record_hash"] = _sha(canonicalize(target["record"]))
    world.put_records(records)
    name = world.leaves_file()
    leaves = world.files[name]
    world.files[name] = leaves[:-32] + bytes.fromhex(target["record_hash"])
    leaf_list = [world.files[name][i:i + 32] for i in range(0, len(world.files[name]), 32)]
    manifest = world.json("manifest.json")
    anchor_name = f"checkpoints/{manifest['checkpoints']['anchor']}.json"
    anchor = world.json(anchor_name)
    entry = anchor["chains"][0]
    entry["head_hash"] = target["record_hash"]
    entry["tree_root"] = merkle.root(merkle.leaf_hash(h) for h in leaf_list).hex()
    leaf = merkle.leaf_hash(canonicalize({k: entry[k] for k in ("tenant_id", "chain_id", "head_seq", "head_hash",
                                                                "tree_size", "tree_root")}))
    anchor["statement"]["chains_root"] = _root_from_path(leaf, entry["leaf_index"],
                                                         anchor["statement"]["chain_count"], entry["path"]).hex()
    anchor["signature"] = insider.sign(anchor["statement"])
    world.put(anchor_name, anchor)
    for chain in manifest["chains"]:
        chain["tree_root"] = entry["tree_root"]
    world.put("manifest.json", manifest)
    lines = []
    for raw in world.files["attestations.dsse.jsonl"].decode().splitlines():
        env = json.loads(raw)
        statement = json.loads(base64.b64decode(env["payload"]))
        predicate = statement["predicate"]
        if predicate.get("record", {}).get("record_hash") == old_hash:
            predicate["record"]["record_hash"] = target["record_hash"]
            predicate["outcome"] = target["record"]["outcome"]
            statement["subject"][0]["digest"]["sha256"] = target["record_hash"]
            env = insider.envelope(statement)
        elif any(r.get("record_hash") == old_hash for r in predicate.get("output_records") or []):
            for r in predicate["output_records"]:
                if r["record_hash"] == old_hash:
                    r["record_hash"] = target["record_hash"]
            env = insider.envelope(statement)
        lines.append(json.dumps(env))
    world.files["attestations.dsse.jsonl"] = ("\n".join(lines) + "\n").encode()
    insider.resign_manifest()


def _root_from_path(leaf: bytes, index: int, size: int, path: list[str]) -> bytes:
    """The root an inclusion path leads to (RFC 9162 §2.1.3.2, computing instead of comparing)."""
    fn, sn, r = index, size - 1, leaf
    for p in (bytes.fromhex(x) for x in path):
        if fn & 1 or fn == sn:
            r = merkle.node_hash(p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = merkle.node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return r


def test_a_chain_rewritten_after_its_checkpoint_is_caught_by_the_timestamp(export):
    """PROV-001: an insider with the signing key rewrites the chain consistently and re-signs
    everything; only the RFC 3161 token, over the original statement, gives it away."""
    insider = Insider(export)
    _rewrite_last_record(export, insider)
    report = insider.verify(archive=None)
    assert _failed(report) == {"timestamp"}, report.failures
    assert any("imprint_mismatch" in f for f in report.failures["timestamp"])


def test_a_chain_rewritten_without_a_new_checkpoint_is_caught_by_the_chain_root(export):
    insider = Insider(export)
    records = export.records()
    target = max(records, key=lambda r: r["position"])
    target["record"]["outcome"]["archive_size_bytes"] += 1
    target["record_hash"] = _sha(canonicalize(target["record"]))
    export.put_records(records)
    name = export.leaves_file()
    export.files[name] = export.files[name][:-32] + bytes.fromhex(target["record_hash"])
    insider.resign_manifest()
    assert "chains" in _failed(insider.verify())


def test_dropping_the_timestamp_is_reported_and_fails_when_required(export):
    insider = Insider(export)
    _rewrite_last_record(export, insider)
    manifest = export.json("manifest.json")
    name = f"checkpoints/{manifest['checkpoints']['anchor']}.json"
    anchor = export.json(name)
    anchor["tsa"] = {"status": "untimestamped", "token": None}
    export.put(name, anchor)
    insider.resign_manifest()
    lenient = insider.verify(archive=None)
    assert lenient.valid and any("not timestamped" in w for w in lenient.warnings)
    assert _failed(insider.verify(archive=None, require_timestamp=True)) == {"timestamp"}


def test_checkpoints_a_changed_inclusion_path_or_statement(export):
    insider = Insider(export)
    manifest = export.json("manifest.json")
    name = f"checkpoints/{manifest['checkpoints']['anchor']}.json"
    anchor = export.json(name)
    anchor["chains"][0]["path"][0] = "00" * 32
    export.put(name, anchor)
    insider.resign_manifest()
    assert "checkpoints" in _failed(insider.verify())
    world = World("export")
    insider = Insider(world)
    anchor = world.json(name)
    anchor["statement"]["chain_count"] += 1
    world.put(name, anchor)
    insider.resign_manifest()
    failed = _failed(insider.verify())
    assert {"checkpoints", "timestamp"} <= failed


def test_timestamp_a_changed_token_or_another_tsa(export):
    insider = Insider(export)
    manifest = export.json("manifest.json")
    name = f"checkpoints/{manifest['checkpoints']['anchor']}.json"
    anchor = export.json(name)
    token = bytearray(base64.b64decode(anchor["tsa"]["token"]))
    token[-3] ^= 0x01  # inside the signature
    anchor["tsa"]["token"] = base64.b64encode(bytes(token)).decode()
    export.put(name, anchor)
    insider.resign_manifest()
    assert _failed(insider.verify()) == {"timestamp"}
    world = World("export")
    report = world.verify(tsa_roots=world.other_tsa)
    assert _failed(report) == {"timestamp"} and any("untrusted_certificate" in f for f in report.failures["timestamp"])
    unchecked = World("export").verify(tsa_roots=[])
    assert unchecked.valid and any("--tsa-cert" in w for w in unchecked.warnings)


def test_consistency_a_changed_proof():
    world = World("export-consistency")
    insider = Insider(world)
    consistency = world.json("consistency.json")
    assert consistency["proofs"], "the fixture carries an earlier checkpoint"
    consistency["proofs"][0]["path"][0] = "11" * 32
    world.put("consistency.json", consistency)
    insider.resign_manifest()
    assert _failed(insider.verify()) == {"consistency"}


def test_seal_a_changed_root_or_leaf(export):
    insider = Insider(export)
    seal = export.json("seal.json")
    seal["statement"]["merkle_root"] = seal["merkle_root"] = "00" * 32
    export.put("seal.json", seal)
    insider.resign_manifest()
    assert "seal" in _failed(insider.verify())
    world = World("export")
    insider = Insider(world)
    lines = world.json("lines.json")
    lines["lines"][0]["leaf_hash"] = "00" * 32
    world.put("lines.json", lines)
    insider.resign_manifest()
    assert "seal" in _failed(insider.verify(archive=None))


def test_lines_an_archive_line_changed_or_a_line_naming_another_record(export):
    members = _files(export.archive)
    members["ds.jsonl"] = members["ds.jsonl"].replace(b"tap", b"tab", 1)
    report = export.verify(archive=_zip(members))
    assert _failed(report) == {"lines"}
    world = World("export")
    insider = Insider(world)
    lines = world.json("lines.json")
    other = next(r for r in world.records() if r["record"]["record_type"] == "qa")
    lines["lines"][0]["record_id"], lines["lines"][0]["record_hash"] = other["record_id"], other["record_hash"]
    world.put("lines.json", lines)
    insider.resign_manifest()
    assert "lines" in _failed(insider.verify())


def test_trace_a_cited_record_left_out(export):
    insider = Insider(export)
    records = export.records()
    dropped = next(r for r in records if r["record"]["record_type"] == "deidentify")
    export.put_records([r for r in records if r is not dropped])
    insider.resign_manifest()
    failed = _failed(insider.verify())
    assert "trace" in failed and "attestations" in failed


def test_attestations_a_changed_payload_or_an_unknown_key(export):
    lines = export.files["attestations.dsse.jsonl"].decode().splitlines()
    env = json.loads(lines[0])
    statement = json.loads(base64.b64decode(env["payload"]))
    statement["predicate"]["outcome"] = {"verdict": "PASS"}
    env["payload"] = base64.b64encode(canonicalize(statement)).decode()
    lines[0] = json.dumps(env)
    export.files["attestations.dsse.jsonl"] = ("\n".join(lines) + "\n").encode()
    insider = Insider(export)
    insider.resign_manifest()
    assert _failed(insider.verify()) == {"attestations"}
    world = World("export")
    insider = Insider(world)
    lines = world.files["attestations.dsse.jsonl"].decode().splitlines()
    env = json.loads(lines[0])
    env["signatures"][0]["keyid"] = "f" * 16
    lines[0] = json.dumps(env)
    world.files["attestations.dsse.jsonl"] = ("\n".join(lines) + "\n").encode()
    insider.resign_manifest()
    report = insider.verify()
    assert _failed(report) == {"attestations"} and "unknown_key" in report.failures["attestations"][0]
    world = World("export")
    insider = Insider(world)
    lines = world.files["attestations.dsse.jsonl"].decode().splitlines()
    statement = json.loads(base64.b64decode(json.loads(lines[0])["payload"]))
    statement["predicate"]["outcome"] = {"verdict": "PASS"}
    lines[0] = json.dumps(insider.envelope(statement))  # re-signed, but no longer the record
    world.files["attestations.dsse.jsonl"] = ("\n".join(lines) + "\n").encode()
    insider.resign_manifest()
    assert _failed(insider.verify()) == {"attestations"}


def test_assurance_a_changed_summary(export):
    insider = Insider(export)
    assurance = export.json("assurance.json")
    assurance["statement"]["assurance"]["conversations"] = 99
    export.put("assurance.json", assurance)
    insider.resign_manifest()
    assert _failed(insider.verify()) == {"assurance"}


def _predicate_types(world: World) -> set[str]:
    return {json.loads(base64.b64decode(json.loads(line)["payload"]))["predicateType"]
            for line in world.files["attestations.dsse.jsonl"].decode().splitlines()}


def _repredicate(world: World, insider: Insider, mapping: dict[str, str]) -> None:
    """Re-sign every attestation with its predicate type renamed (the records are unchanged)."""
    lines = []
    for raw in world.files["attestations.dsse.jsonl"].decode().splitlines():
        statement = json.loads(base64.b64decode(json.loads(raw)["payload"]))
        statement["predicateType"] = mapping[statement["predicateType"]]
        lines.append(json.dumps(insider.envelope(statement)))
    world.files["attestations.dsse.jsonl"] = ("\n".join(lines) + "\n").encode()
    insider.resign_manifest()


def test_bundles_sealed_before_the_domain_move_still_verify(any_bundle):
    """A-218: evidence sealed under the earlier domain is append-only and keeps its URIs.

    Every fixture is such a bundle, made by provance-api before 2026-10-22; the
    predicate URI is an identifier, never fetched, so the bundle verifies unchanged.
    """
    assert _predicate_types(any_bundle) == {legacy.GENERATION_PREDICATE, legacy.OUTPUT_PREDICATE}
    report = any_bundle.verify(require_timestamp=True)
    assert report.valid, report.failures


def test_a_bundle_with_the_current_predicates_verifies(export):
    """Bundles made after A-218 name their predicates under provancelabs.org."""
    assert GENERATION_PREDICATE.startswith("https://provancelabs.org/")
    assert OUTPUT_PREDICATE.startswith("https://provancelabs.org/")
    insider = Insider(export)
    _repredicate(export, insider, {legacy.GENERATION_PREDICATE: GENERATION_PREDICATE,
                                   legacy.OUTPUT_PREDICATE: OUTPUT_PREDICATE})
    assert _predicate_types(export) == {GENERATION_PREDICATE, OUTPUT_PREDICATE}
    report = insider.verify(require_timestamp=True)
    assert report.valid, report.failures


def test_a_predicate_under_any_other_domain_is_refused(export):
    insider = Insider(export)
    _repredicate(export, insider, {
        legacy.GENERATION_PREDICATE: GENERATION_PREDICATE.replace("provancelabs.org", "example.org"),
        legacy.OUTPUT_PREDICATE: OUTPUT_PREDICATE,
    })
    report = insider.verify()
    assert _failed(report) == {"attestations"}
    assert any("unknown predicate type" in f for f in report.failures["attestations"])


def test_not_a_bundle():
    with pytest.raises(BundleError):
        verify_bundle(b"not a zip", trusted_keys={})
    with pytest.raises(BundleError):
        verify_bundle(_zip({"manifest.json": b'{"format": "other"}'}), trusted_keys={})


# ---------------------------------------------------------------------------
# A convert/dispatch seal on its own
# ---------------------------------------------------------------------------


def test_a_convert_seal_verifies_against_its_output_and_catches_a_change():
    paths = _set("convert")
    trusted = keyset.load_key_set(paths["provance-keys.json"])
    seal = json.loads(paths["seal.json"].read_text())
    body = paths["output.jsonl"].read_bytes()
    assert verify_seal(seal, [body], trusted_keys=trusted).valid
    assert _failed(verify_seal(seal, [body.replace(b"assistant", b"Assistant", 1)], trusted_keys=trusted)) == {"lines"}
    forged = copy.deepcopy(seal)
    forged["statement"]["tree_size"] = forged["tree_size"] = 1
    assert "seal" in _failed(verify_seal(forged, [body], trusted_keys=trusted))
    assert cli.main(["--seal", str(paths["seal.json"]), "--keys", str(paths["provance-keys.json"]),
                     str(paths["output.jsonl"])]) == 0


# ---------------------------------------------------------------------------
# Building blocks against known values
# ---------------------------------------------------------------------------


def test_jcs_matches_rfc_8785():
    assert canonicalize({"b": [1, 2.5, 1e21, 1e-7, -0.0], "a": "é\n", "€": True, "\U0001F600": None}) == (
        '{"a":"é\\n","b":[1,2.5,1e+21,1e-7,0],"€":true,"\U0001F600":null}'.encode()
    )
    assert canonicalize(333333333.3333333) == b"333333333.3333333"


def test_merkle_root_and_proofs():
    leaves = [merkle.leaf_hash(bytes([i])) for i in range(7)]
    # MTH(7) = node(MTH(0..4), node(MTH(4..6), d6))
    left = merkle.node_hash(merkle.node_hash(leaves[0], leaves[1]), merkle.node_hash(leaves[2], leaves[3]))
    right = merkle.node_hash(merkle.node_hash(leaves[4], leaves[5]), leaves[6])
    assert merkle.root(leaves) == merkle.node_hash(left, right)
    assert merkle.root([]) == hashlib.sha256(b"").digest()
    # PATH(6, D[7]) = [MTH(4..6), MTH(0..4)]
    assert merkle.verify_inclusion(leaves[6], 6, 7, [merkle.node_hash(leaves[4], leaves[5]), left],
                                   merkle.root(leaves))
    # PROOF(4, D[7]) = [MTH(4..7)] (4 is a power of two: the old root is the first node)
    assert merkle.verify_consistency(4, 7, left, merkle.root(leaves), [right])
    assert not merkle.verify_consistency(4, 7, left, merkle.root(leaves), [left])
