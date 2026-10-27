import pytest

from bayyina_guard.passwords import hash_password, needs_rehash, verify_password
from bayyina_guard.policy import Document, User, authorize
from bayyina_guard.validation import ValidationError, validate_upload

PDF = "application/pdf"


def upload(**over):
    meta = {"filename": "عقد توريد 2026.pdf", "content_type": PDF, "size_bytes": 48_213,
            "matter_id": "MAT-2026-00042", "first_bytes": b"%PDF-1.7\n"}
    meta.update(over)
    return meta


def test_arabic_filename_is_accepted_and_renamed():
    clean = validate_upload(upload())
    assert clean.display_name == "عقد توريد 2026.pdf"
    assert clean.stored_name.endswith(".pdf") and "عقد" not in clean.stored_name


def test_all_errors_are_reported_together():
    with pytest.raises(ValidationError) as exc:
        validate_upload(upload(filename="../../etc/passwd", size_bytes=0, matter_id="42"))
    assert {"filename", "size_bytes", "matter_id"} <= exc.value.errors.keys()


def test_client_cannot_read_another_clients_contract():
    doc = Document(id="d1", client_id="CL-ELNOUR", matter_id="MAT-2026-00042")
    mallory = User(id="u9", role="client", client_id="CL-OTHER")
    d = authorize(mallory, "read", doc)
    assert d.allowed is False and d.reason == "tenant_mismatch"


def test_associate_on_the_matter_can_comment():
    doc = Document(id="d1", client_id="CL-ELNOUR", matter_id="MAT-2026-00042")
    omar = User(id="u2", role="associate", matters=frozenset({"MAT-2026-00042"}))
    assert authorize(omar, "comment", doc).allowed


def test_password_round_trip():
    stored = hash_password("Nile-river-2026")
    assert stored.startswith("scrypt$") and "Nile" not in stored
    assert verify_password("Nile-river-2026", stored)
    assert not verify_password("nile-river-2026", stored)
    assert not needs_rehash(stored)
