"""Password storage for Bayyina's local break-glass accounts. Rules: README.md, "What to build", part 3."""
from __future__ import annotations


def hash_password(password: str) -> str:
    """scrypt$<n>$<r>$<p>$<salt>$<hash> with n=2**14, r=8, p=5, a 16-byte random salt, dklen=32."""
    raise NotImplementedError


def verify_password(password: str, stored: str) -> bool:
    """True only if `password` matches `stored`. Never raises: anything malformed is False."""
    raise NotImplementedError


def needs_rehash(stored: str) -> bool:
    """True if `stored` cannot be parsed or any of n, r, p is below the current values."""
    raise NotImplementedError
