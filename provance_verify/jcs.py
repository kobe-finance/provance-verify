# Copyright 2026 Provance
# SPDX-License-Identifier: Apache-2.0
"""RFC 8785 JSON Canonicalization Scheme (JCS): the bytes Provance hashes and signs."""

from __future__ import annotations

import math
from decimal import Decimal
from typing import Any

_SHORT = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r"}


class JCSError(ValueError):
    """The value is outside the JSON data model RFC 8785 canonicalises."""


def canonicalize(value: Any) -> bytes:
    """The RFC 8785 form of a JSON value as UTF-8 bytes."""
    out: list[str] = []
    _write(value, out)
    return "".join(out).encode("utf-8")


def _write(value: Any, out: list[str]) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, str):
        out.append(_string(value))
    elif isinstance(value, int):
        if abs(value) > 2**53:
            raise JCSError("integer outside the range a double holds exactly")
        out.append(str(value))
    elif isinstance(value, float):
        out.append(_number(value))
    elif isinstance(value, dict):
        out.append("{")
        for i, key in enumerate(sorted(value, key=lambda k: k.encode("utf-16-be"))):
            if not isinstance(key, str):
                raise JCSError("object member names must be strings")
            if i:
                out.append(",")
            out.append(_string(key))
            out.append(":")
            _write(value[key], out)
        out.append("}")
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _write(item, out)
        out.append("]")
    else:
        raise JCSError(f"{type(value).__name__} is not JSON")


def _string(text: str) -> str:
    out = ['"']
    for char in text:
        code = ord(char)
        if char == '"':
            out.append('\\"')
        elif char == "\\":
            out.append("\\\\")
        elif code < 0x20:
            out.append(_SHORT.get(code) or f"\\u{code:04x}")
        elif 0xD800 <= code <= 0xDFFF:
            raise JCSError("lone surrogate")
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def _number(value: float) -> str:
    """ECMAScript Number.prototype.toString of a double."""
    if math.isnan(value) or math.isinf(value):
        raise JCSError("NaN and infinities are not JSON")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    digits_tuple, exponent = Decimal(repr(abs(value))).as_tuple()[1:]
    raw = "".join(str(d) for d in digits_tuple)
    digits = raw.rstrip("0")
    exponent += len(raw) - len(digits)
    k, n = len(digits), exponent + len(digits)
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        body = (digits if k == 1 else digits[0] + "." + digits[1:]) + f"e{'+' if e >= 0 else '-'}{abs(e)}"
    return sign + body
