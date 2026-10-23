# Copyright 2026 Provance
# SPDX-License-Identifier: Apache-2.0
"""A minimal DER reader: just enough ASN.1 to check an RFC 3161 token.

It parses definite-length DER (no BER) into nodes that keep their exact
bytes, so a signature can be checked over the bytes that were signed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

SEQUENCE = 0x30
SET = 0x31
INTEGER = 0x02
OCTET_STRING = 0x04
OID = 0x06
BOOLEAN = 0x01
GENERALIZED_TIME = 0x18


class DERError(ValueError):
    """The bytes are not the DER this reader understands."""


@dataclass(frozen=True)
class Node:
    """One TLV: its identifier byte, its content, and its exact encoding."""

    tag: int
    content: bytes
    raw: bytes

    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)

    def context(self, number: int) -> bool:
        """Whether this is the context-specific tag [number]."""
        return self.tag & 0xC0 == 0x80 and self.tag & 0x1F == number

    def children(self) -> list["Node"]:
        if not self.constructed:
            raise DERError(f"tag 0x{self.tag:02x} is not constructed")
        return parse_all(self.content)


def parse(data: bytes, offset: int = 0) -> tuple[Node, int]:
    """The TLV at ``offset`` and the offset after it."""
    if offset + 2 > len(data):
        raise DERError("truncated")
    tag = data[offset]
    if tag & 0x1F == 0x1F:
        raise DERError("multi-byte tags are not used here")
    first = data[offset + 1]
    pos = offset + 2
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise DERError("indefinite lengths are BER, not DER")
    else:
        count = first & 0x7F
        if count > 4 or pos + count > len(data):
            raise DERError("bad length")
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    end = pos + length
    if end > len(data):
        raise DERError("truncated content")
    return Node(tag, data[pos:end], data[offset:end]), end


def parse_one(data: bytes) -> Node:
    """Exactly one TLV (no trailing bytes)."""
    node, end = parse(data)
    if end != len(data):
        raise DERError("trailing bytes")
    return node


def parse_all(data: bytes) -> list[Node]:
    nodes, offset = [], 0
    while offset < len(data):
        node, offset = parse(data, offset)
        nodes.append(node)
    return nodes


def expect(node: Node, tag: int, what: str) -> Node:
    if node.tag != tag:
        raise DERError(f"{what}: expected tag 0x{tag:02x}, found 0x{node.tag:02x}")
    return node


def oid(node: Node) -> str:
    """An OBJECT IDENTIFIER as dotted text."""
    expect(node, OID, "object identifier")
    data = node.content
    if not data:
        raise DERError("empty object identifier")
    parts: list[int] = []
    value = 0
    for byte in data:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    first = parts[0]
    head = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    return ".".join(str(p) for p in head + parts[1:])


def integer(node: Node) -> int:
    expect(node, INTEGER, "integer")
    return int.from_bytes(node.content, "big", signed=True)


def octets(node: Node) -> bytes:
    return expect(node, OCTET_STRING, "octet string").content


def generalized_time(node: Node) -> datetime:
    """A GeneralizedTime (YYYYMMDDHHMMSS[.fraction]Z) as an aware UTC datetime."""
    text = expect(node, GENERALIZED_TIME, "generalized time").content.decode("ascii")
    if not text.endswith("Z"):
        raise DERError("GeneralizedTime must be UTC (Z)")
    body = text[:-1]
    whole, _, fraction = body.partition(".")
    moment = datetime.strptime(whole, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    if fraction:
        moment = moment.replace(microsecond=int((fraction + "000000")[:6]))
    return moment
