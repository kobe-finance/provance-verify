# Copyright 2026 Provance
# SPDX-License-Identifier: Apache-2.0
"""The trusted key set, and Ed25519 signatures checked by key id.

The key set is the JSON published at ``GET /v1/engine/provenance/public-key``,
fetched by the person verifying, never taken from the bundle. A signature
names its key by ``key_id``; a key carried in the signed object is never
used. A retired key verifies only what was made before it was retired.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from provance_verify.jcs import JCSError, canonicalize

ALGORITHM = "Ed25519"
CANONICALIZATION = "RFC 8785 (JCS)"


class KeySetError(ValueError):
    """The trusted key set cannot be read."""


@dataclass(frozen=True)
class TrustedKey:
    key_id: str
    public_key: Ed25519PublicKey
    status: str
    retired_at: datetime | None


def key_id_for(raw_public_key: bytes) -> str:
    """Provance's key id: the first 16 hex characters of SHA-256 over the raw 32-byte key."""
    return hashlib.sha256(raw_public_key).hexdigest()[:16]


def load_key_set(path: str | Path) -> dict[str, TrustedKey]:
    """The key set published by Provance (``keys``: current and retired keys), by key id.

    Each key's id is recomputed from the key itself; a mismatch is refused.

    Raises:
        KeySetError: the file is not a key set.
    """
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise KeySetError(f"{path}: cannot read the key set: {exc}") from exc
    entries = data.get("keys") if isinstance(data, dict) else None
    if not isinstance(entries, list) or not entries:
        raise KeySetError(f"{path}: no 'keys' list (download GET /v1/engine/provenance/public-key)")
    keys: dict[str, TrustedKey] = {}
    for entry in entries:
        try:
            raw = base64.b64decode(entry["public_key"], validate=True)
            public = Ed25519PublicKey.from_public_bytes(raw)
        except (KeyError, TypeError, ValueError, binascii.Error) as exc:
            raise KeySetError(f"{path}: a key cannot be read") from exc
        if entry.get("key_id") != key_id_for(raw):
            raise KeySetError(f"{path}: key {entry.get('key_id')} does not match its public key")
        retired = entry.get("retired_at")
        keys[entry["key_id"]] = TrustedKey(
            key_id=entry["key_id"], public_key=public, status=str(entry.get("status") or "current"),
            retired_at=datetime.fromisoformat(retired) if retired else None,
        )
    return keys


@dataclass(frozen=True)
class SignatureResult:
    valid: bool
    reason: str  # valid | unknown_key | bad_signature | malformed | key_retired
    key_id: str | None = None


def verify_block(data: Mapping[str, Any], block: Any, keys: Mapping[str, TrustedKey],
                 *, signed_at: str | None) -> SignatureResult:
    """A detached Provance signature block over the RFC 8785 form of ``data``."""
    if not isinstance(block, Mapping) or block.get("algorithm") != ALGORITHM:
        return SignatureResult(False, "malformed")
    if block.get("canonicalization") != CANONICALIZATION:
        return SignatureResult(False, "malformed")
    key_id = block.get("key_id")
    if not isinstance(key_id, str):
        return SignatureResult(False, "malformed")
    key = keys.get(key_id)
    if key is None:
        return SignatureResult(False, "unknown_key", key_id)
    try:
        signature = base64.b64decode(block.get("value") or "", validate=True)
        message = canonicalize(dict(data))
    except (binascii.Error, ValueError, JCSError):
        return SignatureResult(False, "malformed", key_id)
    return _verify(key, signature, message, signed_at)


def verify_bytes(key_id: str, signature: bytes, message: bytes, keys: Mapping[str, TrustedKey],
                 *, signed_at: str | None = None) -> SignatureResult:
    """An Ed25519 signature over raw bytes (a DSSE envelope's PAE)."""
    key = keys.get(key_id)
    if key is None:
        return SignatureResult(False, "unknown_key", key_id)
    return _verify(key, signature, message, signed_at)


def _verify(key: TrustedKey, signature: bytes, message: bytes, signed_at: str | None) -> SignatureResult:
    try:
        key.public_key.verify(signature, message)
    except InvalidSignature:
        return SignatureResult(False, "bad_signature", key.key_id)
    if key.retired_at is not None:
        try:
            made = datetime.fromisoformat(str(signed_at or "").replace("Z", "+00:00"))
        except ValueError:
            return SignatureResult(False, "malformed", key.key_id)
        if made > key.retired_at:
            return SignatureResult(False, "key_retired", key.key_id)
    return SignatureResult(True, "valid", key.key_id)
