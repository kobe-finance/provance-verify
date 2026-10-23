# provance-verify

Check a Provance evidence bundle **offline**, without trusting Provance's
database or servers. Apache-2.0 (see `LICENSE` and `NOTICE`). One dependency:
`cryptography`; everything else is the Python standard library.

Public repository: <https://github.com/kobe-finance/provance-verify>.
More about Provance evidence: <https://provancelabs.org/evidence>.

An evidence bundle is what Provance gives you for an export or a Synthetic
batch: every provenance record needed to trace each exported line back to its
first inputs (gold standards, ontology, scenario register, domain
configuration, model calls), the chains they are on, the signed seal over the
output, and a signed checkpoint timestamped by an RFC 3161 time-stamp
authority. It holds hashes, ids, versions, counts and verdicts only: no
conversation text, prompt or reviewer note. Hashes of guessable values
(drafts before de-identification, raw uploads, review decisions) are the
organisation's keyed hashes (HMAC-SHA256, `keyed_by` names the key).

## Install

Python 3.12 or later.

```bash
pip install git+https://github.com/kobe-finance/provance-verify
pip install 'provance-verify[parquet] @ git+https://github.com/kobe-finance/provance-verify'
#   [parquet] also reads Parquet files in an export archive (pyarrow)
```

Pin a release with `@<tag>` after the URL. A PyPI release
(`pip install provance-verify`) will follow.

## Offline by design

The verifier makes no network connection. It reads only the files you give
it: the bundle, your copy of Provance's public key set, the timestamp
authority's certificate and, optionally, the export archive. Fetch the key set
and the TSA certificate yourself, once, from their sources; then verification
can run on an air-gapped machine.

URIs inside a bundle (in-toto predicate types, statement types, PROV
namespaces) are identifiers, never fetched. Bundles sealed before 2026-10-22
name Provance's predicates under the earlier `.com` domain in place of
`provancelabs.org`; sealed evidence is append-only, so those bundles keep
their URIs and the verifier accepts both forms (`provance_verify/legacy.py`).
Nothing is ever contacted at either domain.

## Verify an export

```bash
# 1. Download the bundle and the export from Provance (signed in, or with an API key):
#    GET /v1/format/export/{job_id}/evidence  -> ds_evidence.zip
#    GET /v1/format/export/{job_id}/download  -> ds_export.zip
# 2. Get Provance's key set yourself (it is public); never use the copy inside the bundle:
curl -s https://<provance-api>/v1/engine/provenance/public-key > provance-keys.json
# 3. Get the timestamp authority's certificate from the TSA itself
#    (development uses FreeTSA: https://freetsa.org/files/cacert.pem).
# 4. Verify:
provance-verify ds_evidence.zip --keys provance-keys.json --tsa-cert tsa.pem --export ds_export.zip
```

A batch's bundle (`GET /v1/synthetic/batches/{batch_id}/evidence`) is checked
the same way, without `--export`.

A `/convert` or `/dispatch` output carries its own seal (in the response, and
in the dispatch manifest). Check the lines you received against it:

```bash
provance-verify --seal seal.json --keys provance-keys.json output.jsonl
# dispatch: give the files in the order of the response's `locations`
```

Exit status: `0` verified, `1` a check failed, `2` the input could not be
read. `--json` prints the result as JSON. `--require-timestamp` fails when a
checkpoint is not timestamped (or no `--tsa-cert` is given) instead of
warning.

## What is checked

| Layer | Check |
|---|---|
| manifest | `manifest.json` is signed by a key in **your** key set (chosen by `key_id`; a key inside the bundle is never used; a retired key only verifies what was made before it was retired), and every other file matches its SHA-256 there, with none missing or added |
| records | every record's hash is SHA-256 over its RFC 8785 (JCS) form |
| chains | each chain's record hashes (`chains/*.leaves`) give the RFC 9162 Merkle root the anchor checkpoint signed; every record is at its position; every record links to the one before it (`prev_hash`) |
| checkpoints | each checkpoint's statement is signed, and each chain entry is included in its signed root |
| timestamp | each checkpoint's RFC 3161 token is over SHA-256 of exactly that statement, with its nonce; the CMS signature verifies; the signer has the critical time-stamping key usage and chains to the certificate you gave, valid at the token's time |
| consistency | each earlier checkpoint's tree of a chain is a prefix of the anchor's (RFC 9162 consistency proof) |
| seal | the seal is signed, its leaves give its root, and it is recorded on the chain |
| lines | every exported line names the record of its version, or carries a label such as "recorded before provenance tracking"; with `--export`, every line's bytes, every file and the archive match |
| trace | every input a record cites (another record, a stored version) is in the bundle with the hash it was cited with, or is listed as having no record |
| attestations | every in-toto Statement in `attestations.dsse.jsonl` is DSSE-signed by a key in your set and agrees with the record or output it describes |
| assurance | the signed assurance summary names this seal and archive |

What it shows: the output is exactly what was sealed; the records behind it
are the ones on Provance's chains; those chains were as they are now when the
timestamp authority stamped the checkpoint, so they were not rewritten
afterwards, even by someone holding Provance's signing key.

What it does not show: anything a record does not say. Lines labelled
"recorded before provenance tracking" have no records, and nothing is
claimed about how they were made.

## Bundle format (`provance-evidence-bundle`, version 1)

| File | Content |
|---|---|
| `manifest.json` | scope (`export` or `batch`) and id, tenant, the output (archive and file hashes), the seal, each chain (tree size and root), the checkpoints used, stored versions cited without a record (with their label), every other file's SHA-256; `signature` over its RFC 8785 form without the signature |
| `records/<chain>.jsonl` | one record per line: `position` on the chain, `seq`, `record_id`, `record_hash`, `record` (format 2: subject, activity, inputs, model call, policies, actor, outcome) |
| `chains/<chain>.leaves` | the chain's record hashes, 32 bytes each, in chain order, up to the anchor checkpoint's tree size |
| `checkpoints/<id>.json` | `statement` (checkpoint type, sequence, previous checkpoint, time, chain count, `chains_root`), `signature`, `tsa` (status, base64 DER `token`, `nonce`, time), and this tenant's chain entries with their `leaf_index` and inclusion `path`. Chain entry leaf: RFC 8785 bytes of `{chain_id, head_hash, head_seq, tenant_id, tree_root, tree_size}` |
| `consistency.json` | RFC 9162 consistency proofs from each earlier checkpoint to the anchor |
| `seal.json` | the seal: signed statement (scope, root, tree size, leaf kind, time), its leaves (batch: record hashes), its chain record |
| `lines.json` | exports: every line (`file`, `line`, `sha256`, `leaf_hash` = SHA-256(0x00 ‖ line bytes)) and the record it names, or its `label` |
| `attestations.dsse.jsonl` | DSSE envelopes (payload type `application/vnd.in-toto+json`) around in-toto Statements v1: predicate `https://provancelabs.org/attestations/generation/v1` per record (SLSA-shaped: `buildDefinition`, `runDetails`, the model call, policies, actor and outcome) and `https://provancelabs.org/attestations/output/v1` for the export or batch. Bundles sealed before 2026-10-22 name the same predicates with `.com` in place of `.org` (A-218); they are accepted unchanged, because a predicate URI is an identifier and is never fetched |
| `prov.json` | a W3C PROV-JSON view of the same records |
| `dataset_card.json` | exports: a Croissant 1.1 + RAI 1.0 card, from the records only |
| `assurance.json` | exports: the assurance summary bound to the seal and archive, signed |
| `keys.json`, `tsa-certificates.pem` | copies for reference only |

Merkle trees follow RFC 9162: leaf hash SHA-256(0x00 ‖ leaf), node hash
SHA-256(0x01 ‖ left ‖ right). Chain tree leaves are the 32 raw bytes of each
record hash.

## Development

```bash
poetry install && poetry run pytest -q
```

The fixtures in `tests/fixtures` are real bundles made by Provance's API test
suite with synthetic data: a local test TSA, and a development signing key
made for the run. They hold public keys and certificates only.

## Contributing and security

Report a vulnerability privately as described in [SECURITY.md](SECURITY.md).
This repository is published from Provance's SDK monorepo, where the verifier
is maintained; pull requests are welcome here and are carried over there.
