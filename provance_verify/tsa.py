# Copyright 2026 Provance
# SPDX-License-Identifier: Apache-2.0
"""RFC 3161 time-stamp tokens, checked offline against the TSA certificate you trust.

A token is CMS SignedData (RFC 5652) over a TSTInfo. It verifies when:

- its TSTInfo's message imprint is SHA-256 of exactly the checkpoint
  statement, and its nonce is the one the checkpoint recorded;
- its signed attributes name the TSTInfo content type and digest, and
  SigningCertificate(V2) names the signing certificate;
- the CMS signature verifies with that certificate, which has the critical
  time-stamping extended key usage (RFC 3161 §2.3) and chains, by signatures,
  to a certificate given with ``--tsa-cert``; every certificate on the path
  was valid at the token's time.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID

from provance_verify import der

ID_SIGNED_DATA = "1.2.840.113549.1.7.2"
ID_CT_TST_INFO = "1.2.840.113549.1.9.16.1.4"
ID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
ID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
ID_SIGNING_CERTIFICATE = "1.2.840.113549.1.9.16.2.12"
ID_SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47"
ID_SHA256 = "2.16.840.1.101.3.4.2.1"
_DIGESTS = {
    "2.16.840.1.101.3.4.2.1": ("sha256", hashes.SHA256),
    "2.16.840.1.101.3.4.2.2": ("sha384", hashes.SHA384),
    "2.16.840.1.101.3.4.2.3": ("sha512", hashes.SHA512),
}
_RSA_PSS = "1.2.840.113549.1.1.10"


class TokenError(ValueError):
    """The token does not verify (``reason`` says why)."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class Timestamp:
    gen_time: datetime
    serial_number: int
    policy: str
    nonce: int | None
    tsa_subject: str


def load_certificates(paths: Sequence[str]) -> list[x509.Certificate]:
    certs: list[x509.Certificate] = []
    for path in paths:
        with open(path, "rb") as handle:
            certs.extend(x509.load_pem_x509_certificates(handle.read()))
    return certs


def _digest(oid: str, data: bytes) -> bytes:
    if oid not in _DIGESTS:
        raise TokenError("unsupported_algorithm", f"digest algorithm {oid} is not supported")
    return hashlib.new(_DIGESTS[oid][0], data).digest()


def _attributes(node: der.Node) -> dict[str, list[der.Node]]:
    out: dict[str, list[der.Node]] = {}
    for attribute in node.children():
        oid_node, values = attribute.children()
        out.setdefault(der.oid(oid_node), []).extend(der.expect(values, der.SET, "attribute values").children())
    return out


def _one(attributes: dict[str, list[der.Node]], oid: str) -> der.Node | None:
    values = attributes.get(oid)
    if values is None:
        return None
    if len(values) != 1:
        raise TokenError("malformed_token", f"signed attribute {oid} must have exactly one value")
    return values[0]


def _signer(sid: der.Node, candidates: Sequence[x509.Certificate]) -> x509.Certificate:
    if sid.tag == der.SEQUENCE:
        issuer, serial = sid.children()
        for cert in candidates:
            if cert.serial_number == der.integer(serial) and cert.issuer.public_bytes() == issuer.raw:
                return cert
    elif sid.context(0):
        for cert in candidates:
            try:
                ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
            except x509.ExtensionNotFound:
                continue
            if ski == sid.content:
                return cert
    raise TokenError("untrusted_certificate", "the token's signer certificate is not in the token or trusted")


def _check_signing_certificate(attributes: dict[str, list[der.Node]], signer: x509.Certificate) -> None:
    cert_der = signer.public_bytes(Encoding.DER)
    v2 = _one(attributes, ID_SIGNING_CERTIFICATE_V2)
    if v2 is not None:
        first = v2.children()[0].children()[0].children()
        algorithm = ID_SHA256
        if first[0].tag == der.SEQUENCE:
            algorithm = der.oid(first[0].children()[0])
            first = first[1:]
        if _digest(algorithm, cert_der) != der.octets(first[0]):
            raise TokenError("signing_certificate_mismatch", "SigningCertificateV2 does not name the signer")
        return
    v1 = _one(attributes, ID_SIGNING_CERTIFICATE)
    if v1 is not None:
        cert_hash = der.octets(v1.children()[0].children()[0].children()[0])
        if hashlib.sha1(cert_der).digest() != cert_hash:  # noqa: S324 (ESSCertID is SHA-1 by definition)
            raise TokenError("signing_certificate_mismatch", "SigningCertificate does not name the signer")
        return
    raise TokenError("signing_certificate_mismatch", "the token names no signing certificate (RFC 3161 requires one)")


def _verify_signature(cert: x509.Certificate, signature: bytes, data: bytes, digest_oid: str, sig_oid: str) -> None:
    if sig_oid == _RSA_PSS:
        raise TokenError("unsupported_algorithm", "RSASSA-PSS token signatures are not supported")
    key = cert.public_key()
    try:
        if isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, data)
            return
        if digest_oid not in _DIGESTS:
            raise TokenError("unsupported_algorithm", f"digest algorithm {digest_oid} is not supported")
        algorithm = _DIGESTS[digest_oid][1]()
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, data, padding.PKCS1v15(), algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, data, ec.ECDSA(algorithm))
        else:
            raise TokenError("unsupported_algorithm", f"{type(key).__name__} keys are not supported")
    except InvalidSignature as exc:
        raise TokenError("bad_signature", "the token's signature does not verify") from exc


def _check_chain(signer: x509.Certificate, pool: Sequence[x509.Certificate],
                 trusted: Sequence[x509.Certificate], moment: datetime) -> None:
    trusted_der = {c.public_bytes(Encoding.DER) for c in trusted}
    current = signer
    for _ in range(6):
        if not current.not_valid_before_utc <= moment <= current.not_valid_after_utc:
            raise TokenError("certificate_not_valid_at_time",
                             f"{current.subject.rfc4514_string()} was not valid at the token's time")
        if current.public_bytes(Encoding.DER) in trusted_der:
            return
        for issuer in (c for c in (*trusted, *pool) if c.subject == current.issuer and c is not current):
            try:
                current.verify_directly_issued_by(issuer)
            except (ValueError, TypeError, InvalidSignature):
                continue
            current = issuer
            break
        else:
            raise TokenError("untrusted_certificate", "the TSA's certificate does not chain to a trusted certificate")
    raise TokenError("untrusted_certificate", "the TSA's certificate chain is too long")


def verify_token(token: bytes, *, digest: bytes, nonce: int | None,
                 trusted: Sequence[x509.Certificate]) -> Timestamp:
    """Check an RFC 3161 token over ``digest`` (see the module docstring).

    Raises:
        TokenError: the token does not verify.
    """
    try:
        return _verify(token, digest, nonce, trusted)
    except der.DERError as exc:
        raise TokenError("malformed_token", f"the token cannot be read: {exc}") from exc


def _verify(token: bytes, digest: bytes, nonce: int | None, trusted: Sequence[x509.Certificate]) -> Timestamp:
    content_type, content = der.parse_one(token).children()
    if der.oid(content_type) != ID_SIGNED_DATA or not content.context(0):
        raise TokenError("malformed_token", "the token is not CMS SignedData")
    signed = der.parse_one(content.content).children()
    encap = signed[2].children()
    if der.oid(encap[0]) != ID_CT_TST_INFO or len(encap) != 2 or not encap[1].context(0):
        raise TokenError("malformed_token", "the token does not carry a TSTInfo")
    tst_der = der.octets(der.parse_one(encap[1].content))
    tst = der.parse_one(tst_der).children()
    if der.integer(tst[0]) != 1:
        raise TokenError("malformed_token", "the TSTInfo version is not 1")
    imprint_alg, imprint = tst[2].children()
    if der.oid(imprint_alg.children()[0]) != ID_SHA256 or der.octets(imprint) != digest:
        raise TokenError("imprint_mismatch", "the token timestamps a different value than this checkpoint")
    serial = der.integer(tst[3])
    gen_time = der.generalized_time(tst[4])
    token_nonce = next((der.integer(n) for n in tst[5:] if n.tag == der.INTEGER), None)
    if nonce is not None and token_nonce != nonce:
        raise TokenError("nonce_mismatch", "the token's nonce is not the checkpoint's: it answers another request")

    pool: list[x509.Certificate] = []
    signer_infos = signed[-1]
    for node in signed[3:-1]:
        if node.context(0):
            pool = [x509.load_der_x509_certificate(c.raw) for c in node.children()]
    infos = der.expect(signer_infos, der.SET, "signer infos").children()
    if len(infos) != 1:
        raise TokenError("malformed_token", "the token must have exactly one signer")
    info = infos[0].children()
    sid, digest_alg = info[1], info[2]
    signed_attrs = next((n for n in info[3:] if n.context(0)), None)
    if signed_attrs is None:
        raise TokenError("malformed_token", "the token has no signed attributes")
    rest = [n for n in info[3:] if not n.context(0) and not n.context(1)]
    signature_alg, signature = rest[0], rest[1]
    attributes = _attributes(signed_attrs)
    content_type_value = _one(attributes, ID_CONTENT_TYPE)
    if content_type_value is None or der.oid(content_type_value) != ID_CT_TST_INFO:
        raise TokenError("content_mismatch", "the token's signed content type is not TSTInfo")
    digest_oid = der.oid(digest_alg.children()[0])
    message_digest = _one(attributes, ID_MESSAGE_DIGEST)
    if message_digest is None or der.octets(message_digest) != _digest(digest_oid, tst_der):
        raise TokenError("content_mismatch", "the token's signed digest does not match its TSTInfo")
    signer = _signer(sid, [*pool, *trusted])
    _check_signing_certificate(attributes, signer)
    # Signed over the DER of the signed attributes as an untagged SET OF (RFC 5652 §5.4).
    _verify_signature(signer, der.octets(signature), b"\x31" + signed_attrs.raw[1:], digest_oid,
                      der.oid(signature_alg.children()[0]))
    try:
        usage = signer.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    except x509.ExtensionNotFound as exc:
        raise TokenError("not_a_tsa_certificate", "the signer certificate has no extended key usage") from exc
    if not usage.critical or list(usage.value) != [ExtendedKeyUsageOID.TIME_STAMPING]:
        raise TokenError("not_a_tsa_certificate", "the signer's extended key usage is not exactly time stamping")
    _check_chain(signer, pool, trusted, gen_time)
    return Timestamp(gen_time=gen_time, serial_number=serial, policy=der.oid(tst[1]), nonce=token_nonce,
                     tsa_subject=signer.subject.rfc4514_string())
