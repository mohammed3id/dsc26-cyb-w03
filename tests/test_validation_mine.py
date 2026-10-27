import re
import unicodedata

import pytest

from bayyina_guard.validation import MAX_BYTES, ValidationError, validate_upload

PDF = "application/pdf"
DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
FIELDS = {"filename", "content_type", "size_bytes", "matter_id", "first_bytes"}


def meta(**over):
    m = {
        "filename": "contract.pdf",
        "content_type": PDF,
        "size_bytes": 1000,
        "matter_id": "MAT-2026-00123",
        "first_bytes": b"%PDF-1.7",
    }
    m.update(over)
    return m


def errors_of(m):
    with pytest.raises(ValidationError) as excinfo:
        validate_upload(m)
    return excinfo.value.errors


def test_valid_pdf():
    r = validate_upload(meta())
    assert r.extension == "pdf"
    assert r.content_type == PDF
    assert r.display_name == "contract.pdf"
    assert r.size_bytes == 1000
    assert r.matter_id == "MAT-2026-00123"
    assert re.fullmatch(r"[0-9a-f]{32}\.pdf", r.stored_name)


def test_valid_docx():
    r = validate_upload(meta(filename="memo.docx", content_type=DOCX, first_bytes=b"PK\x03\x04rest"))
    assert r.extension == "docx" and r.content_type == DOCX
    assert re.fullmatch(r"[0-9a-f]{32}\.docx", r.stored_name)


def test_arabic_filename_with_spaces_is_fine():
    r = validate_upload(meta(filename="عقد توريد.pdf"))
    assert r.display_name == "عقد توريد.pdf"
    assert "عقد" not in r.stored_name


@pytest.mark.parametrize("name", ["..\\x.pdf", "/abs.pdf", "a/b.pdf", ".hidden.pdf", "x..pdf", "x.pdf/"])
def test_path_tricks_rejected(name):
    assert "filename" in errors_of(meta(filename=name))


@pytest.mark.parametrize("name", [
    "عقد\u202bتوريد.pdf", "a\x00b.pdf", "a\nb.pdf", "a\u2066b.pdf",
    "a\u202eb.pdf", "a\u061cb.pdf", "a\u200eb.pdf", "a\u200fb.pdf",
])
def test_invisible_and_control_characters_rejected(name):
    assert "filename" in errors_of(meta(filename=name))


@pytest.mark.parametrize("name", ["LEASE.PDF", "x.exe.pdf"])
def test_last_extension_decides_good(name):
    assert validate_upload(meta(filename=name)).extension == "pdf"


@pytest.mark.parametrize("name", ["x.pdf.exe", "x.", "pdf", ".pdf", "   .pdf", "x.txt", ""])
def test_last_extension_decides_bad(name):
    assert "filename" in errors_of(meta(filename=name))


def test_filename_length_limit():
    assert validate_upload(meta(filename="a" * 116 + ".pdf"))
    assert "filename" in errors_of(meta(filename="a" * 117 + ".pdf"))


def test_non_string_filename():
    for bad in (None, 123, b"x.pdf"):
        assert "filename" in errors_of(meta(filename=bad))


def test_docx_sent_as_pdf():
    errs = errors_of(meta(filename="x.docx"))
    assert "content_type" in errs and "first_bytes" in errs


def test_docx_type_with_pdf_bytes_is_a_first_bytes_error():
    assert set(errors_of(meta(filename="x.docx", content_type=DOCX))) == {"first_bytes"}


def test_pdf_with_wrong_type_is_only_a_content_type_error():
    assert set(errors_of(meta(content_type=DOCX))) == {"content_type"}


def test_first_bytes_must_be_bytes():
    for bad in ("%PDF-", None, 5):
        assert "first_bytes" in errors_of(meta(first_bytes=bad))


def test_bad_filename_only_type_checks_the_rest():
    assert set(errors_of(meta(filename="../x.pdf"))) == {"filename"}


@pytest.mark.parametrize("size", [True, False, 10.0, 0, -5, "10", None, MAX_BYTES + 1])
def test_bad_sizes(size):
    assert "size_bytes" in errors_of(meta(size_bytes=size))


@pytest.mark.parametrize("size", [1, MAX_BYTES])
def test_size_limits_are_inclusive(size):
    assert validate_upload(meta(size_bytes=size)).size_bytes == size


@pytest.mark.parametrize("mid", [
    "MAT-\u0662\u0660\u0662\u0666-00123", "MAT-2026-00123\n", " MAT-2026-00123",
    "mat-2026-00123", "MAT-202-00123", "MAT-2026-0012", "MAT-2026-001234", "", None, 5,
])
def test_bad_matter_ids(mid):
    assert "matter_id" in errors_of(meta(matter_id=mid))


def test_display_name_is_nfc():
    r = validate_upload(meta(filename="cafe\u0301.pdf"))
    assert r.display_name == "caf\u00e9.pdf"
    assert unicodedata.is_normalized("NFC", r.display_name)


def test_stored_names_are_unique():
    names = {validate_upload(meta()).stored_name for _ in range(50)}
    assert len(names) == 50


def test_all_errors_reported_together():
    errs = errors_of({"filename": "../x", "content_type": 123, "size_bytes": 0,
                      "matter_id": "x", "first_bytes": "no"})
    assert set(errs) == FIELDS


def test_empty_metadata_reports_every_field():
    assert set(errors_of({})) == FIELDS
