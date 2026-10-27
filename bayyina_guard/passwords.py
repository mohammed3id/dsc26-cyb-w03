"""Password storage for Bayyina's break-glass accounts. Rules: README.md, part 3."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import unicodedata

# current cost parameters
N, R, P = 2**14, 8, 5
DKLEN = 32
SALT_BYTES = 16
MAXMEM = 64 * 1024 * 1024
B64_RE = re.compile(r"[A-Za-z0-9_-]+")


def _b64e(raw: bytes) -> str:
    """URL-safe base64 without '=' padding."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    """Strict decode: only URL-safe characters, no padding allowed in the stored string."""
    if not B64_RE.fullmatch(text):
        raise ValueError("bad base64")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _normalise(password) -> bytes:
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    text = unicodedata.normalize("NFKC", password)
    if not 8 <= len(text) <= 128:
        raise ValueError("password must be 8 to 128 characters")
    return text.encode("utf-8")


def _derive(pw: bytes, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(pw, salt=salt, n=n, r=r, p=p, maxmem=MAXMEM, dklen=DKLEN)


def _parse(stored):
    """Split "scrypt$n$r$p$salt$hash". Return (n, r, p, salt, key) or None if malformed."""
    if not isinstance(stored, str):
        return None
    parts = stored.split("$")
    if len(parts) != 6 or parts[0] != "scrypt":
        return None
    numbers = []
    for text in parts[1:4]:
        if not (text.isascii() and text.isdigit()) or len(text) > 10:
            return None
        numbers.append(int(text))
    try:
        salt = _b64d(parts[4])
        key = _b64d(parts[5])
    except ValueError:
        return None
    return numbers[0], numbers[1], numbers[2], salt, key


def hash_password(password: str) -> str:
    """scrypt$<n>$<r>$<p>$<salt>$<hash> with n=2**14, r=8, p=5, a 16-byte random salt, dklen=32."""
    pw = _normalise(password)
    salt = os.urandom(SALT_BYTES)
    key = _derive(pw, salt, N, R, P)
    return f"scrypt${N}${R}${P}${_b64e(salt)}${_b64e(key)}"


def verify_password(password: str, stored: str) -> bool:
    """True only for a well-formed stored hash that matches. Never raises."""
    try:
        pw = _normalise(password)
    except (TypeError, ValueError):
        return False
    parsed = _parse(stored)
    if parsed is None:
        return False
    n, r, p, salt, key = parsed
    # check every bound BEFORE running scrypt (a huge p would burn CPU for minutes)
    if not (2 <= n <= 2**20 and n & (n - 1) == 0):
        return False
    if not (1 <= r <= 32 and 1 <= p <= 16):
        return False
    if len(salt) < SALT_BYTES or len(key) != DKLEN:
        return False
    try:
        candidate = _derive(pw, salt, n, r, p)
    except Exception:
        return False
    return hmac.compare_digest(candidate, key)


def needs_rehash(stored: str) -> bool:
    """True if the stored string cannot be parsed or any of n, r, p is below the current values."""
    parsed = _parse(stored)
    if parsed is None:
        return True
    n, r, p, _salt, _key = parsed
    return n < N or r < R or p < P