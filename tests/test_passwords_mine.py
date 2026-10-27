import base64
import hashlib
import time

import pytest

from bayyina_guard.passwords import hash_password, needs_rehash, verify_password

PW = "Nile-river-2026"
GOOD = hash_password(PW)


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def swap(stored, **kw):
    """Replace n, r, p, salt or key in a stored hash without running scrypt."""
    parts = stored.split("$")
    for name, i in (("n", 1), ("r", 2), ("p", 3), ("salt", 4), ("key", 5)):
        if name in kw:
            parts[i] = str(kw[name])
    return "$".join(parts)


def legacy_hash(password, n=4096, r=8, p=1):
    salt = b"s" * 16
    key = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, maxmem=64 * 1024 * 1024, dklen=32)
    return f"scrypt${n}${r}${p}${b64(salt)}${b64(key)}"


def test_round_trip():
    assert verify_password(PW, GOOD) is True
    assert verify_password("another-password", GOOD) is False


def test_two_hashes_of_one_password_differ():
    assert hash_password(PW) != GOOD


def test_exact_format():
    parts = GOOD.split("$")
    assert parts[:4] == ["scrypt", "16384", "8", "5"]
    assert "=" not in GOOD
    assert len(unb64(parts[4])) == 16
    assert len(unb64(parts[5])) == 32


def test_nfc_and_nfd_spellings_match():
    nfc = "caf\u00e9-\u0645\u0631\u062d\u0628\u0627"
    nfd = "cafe\u0301-\u0645\u0631\u062d\u0628\u0627"
    stored = hash_password(nfc)
    assert verify_password(nfd, stored) is True


@pytest.mark.parametrize("bad", ["a" * 7, "a" * 129, ""])
def test_length_limits_raise_value_error(bad):
    with pytest.raises(ValueError):
        hash_password(bad)


@pytest.mark.parametrize("bad", [b"password123", None, 12345678])
def test_non_string_raises_type_error(bad):
    with pytest.raises(TypeError):
        hash_password(bad)


def test_limits_are_inclusive():
    assert hash_password("a" * 8).startswith("scrypt$")
    assert hash_password("a" * 128).startswith("scrypt$")


def test_verify_never_raises_on_bad_passwords():
    assert verify_password("short", GOOD) is False
    assert verify_password(b"password123", GOOD) is False
    assert verify_password(None, GOOD) is False


def test_legacy_hash_verifies_and_needs_rehash():
    old = legacy_hash(PW)
    assert verify_password(PW, old) is True
    assert needs_rehash(old) is True


def test_needs_rehash_rules():
    assert needs_rehash(GOOD) is False
    assert needs_rehash(swap(GOOD, n=2**15)) is False
    assert needs_rehash(swap(GOOD, n=2**13)) is True
    assert needs_rehash(swap(GOOD, r=7)) is True
    assert needs_rehash(swap(GOOD, p=4)) is True
    assert needs_rehash("garbage") is True
    assert needs_rehash(None) is True


MALFORMED = [
    "",
    "scrypt",
    "bcrypt$16384$8$5$" + GOOD.split("$", 4)[4],
    "scrypt$16384$8$5$!!!$!!!",
    GOOD[:-4],                                  # hash truncated by four characters
    GOOD + "AAAA",                              # hash too long
    GOOD + "$extra",
    swap(GOOD, n=3),
    swap(GOOD, n=1),
    swap(GOOD, n=2**21),
    swap(GOOD, r=0),
    swap(GOOD, r=33),
    swap(GOOD, p=0),
    swap(GOOD, p=17),
    swap(GOOD, salt=b64(b"x" * 15)),
    swap(GOOD, key=b64(b"x" * 31)),
    swap(GOOD, key=b64(b"x" * 33)),
    swap(GOOD, key=GOOD.split("$")[5] + "="),   # padding is not allowed
    swap(GOOD, n="\u0661\u0666\u0663\u0668\u0664"),  # non-ASCII digits
]


@pytest.mark.parametrize("stored", MALFORMED)
def test_malformed_stored_values_return_false(stored):
    assert verify_password(PW, stored) is False


@pytest.mark.parametrize("stored", [None, 123, b"scrypt$16384$8$5$a$b", ["x"]])
def test_non_string_stored_returns_false(stored):
    assert verify_password(PW, stored) is False


def test_dos_sized_parameters_return_quickly():
    start = time.time()
    for bad in (swap(GOOD, p=10**9), swap(GOOD, n=2**20, r=32), swap(GOOD, n=2**30)):
        assert verify_password(PW, bad) is False
    assert time.time() - start < 10
