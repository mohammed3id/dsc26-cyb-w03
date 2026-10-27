"""Upload validation for Bayyina. Rules: README.md, "What to build", part 1."""
from __future__ import annotations

import re
import unicodedata
import uuid
from dataclasses import dataclass

MAX_BYTES = 25 * 1024 * 1024

PDF_TYPE = "application/pdf"
DOCX_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
CANONICAL_TYPE = {"pdf": PDF_TYPE, "docx": DOCX_TYPE}
SIGNATURE = {"pdf": b"%PDF-", "docx": b"PK\x03\x04"}
FIELDS = ("filename", "content_type", "size_bytes", "matter_id", "first_bytes")

# U+061C, U+200E, U+200F, U+202A-U+202E, U+2066-U+2069
BIDI_CONTROLS = (
    {"\u061c", "\u200e", "\u200f"}
    | {chr(c) for c in range(0x202A, 0x202F)}
    | {chr(c) for c in range(0x2066, 0x206A)}
)
MATTER_RE = re.compile(r"MAT-[0-9]{4}-[0-9]{5}")


class ValidationError(Exception):
    def __init__(self, errors: dict[str, str]):
        super().__init__("; ".join(f"{k}: {v}" for k, v in errors.items()))
        self.errors = errors


@dataclass(frozen=True)
class CleanUpload:
    stored_name: str      # "<32 hex chars>.<ext>", generated, never derived from the filename
    display_name: str     # the filename after NFC normalisation
    extension: str        # "pdf" or "docx", lowercase
    content_type: str
    size_bytes: int
    matter_id: str


def _check_filename(filename):
    """Return (display_name, extension, None) if valid, else (None, None, error message)."""
    if not isinstance(filename, str):
        return None, None, "must be a string"
    name = unicodedata.normalize("NFC", filename)
    if not 1 <= len(name) <= 120:
        return None, None, "must be 1 to 120 characters"
    for ch in name:
        if unicodedata.category(ch) == "Cc":
            return None, None, "contains a control character"
        if ch in BIDI_CONTROLS:
            return None, None, "contains a bidirectional control character"
    if "/" in name or "\\" in name:
        return None, None, "must not contain a path separator"
    if ".." in name:
        return None, None, "must not contain '..'"
    if name.startswith("."):
        return None, None, "must not start with a dot"
    base, dot, ext = name.rpartition(".")
    if not dot:
        return None, None, "must have an extension"
    ext = ext.lower()
    if ext not in CANONICAL_TYPE:
        return None, None, "extension must be pdf or docx"
    if not base.strip():
        return None, None, "needs a name before the extension"
    return name, ext, None


def validate_upload(meta: dict) -> CleanUpload:
    if not isinstance(meta, dict):
        raise ValidationError({f: "metadata must be a mapping" for f in FIELDS})

    errors: dict[str, str] = {}

    # filename (also gives us the extension the other checks depend on)
    display_name, ext, problem = _check_filename(meta.get("filename"))
    if problem:
        errors["filename"] = problem

    # content_type
    content_type = meta.get("content_type")
    if not isinstance(content_type, str):
        errors["content_type"] = "must be a string"
    elif ext is not None and content_type != CANONICAL_TYPE[ext]:
        errors["content_type"] = "does not match the file extension"

    # first_bytes
    first_bytes = meta.get("first_bytes")
    if not isinstance(first_bytes, bytes):
        errors["first_bytes"] = "must be bytes"
    elif ext is not None and not first_bytes.startswith(SIGNATURE[ext]):
        errors["first_bytes"] = f"does not look like a {ext} file"

    # size_bytes: a real int (bool and float are rejected by the exact type check)
    size = meta.get("size_bytes")
    if type(size) is not int or not 1 <= size <= MAX_BYTES:
        errors["size_bytes"] = f"must be an integer from 1 to {MAX_BYTES}"

    # matter_id: ASCII, exact shape, no trailing newline (fullmatch)
    matter_id = meta.get("matter_id")
    if not isinstance(matter_id, str) or not matter_id.isascii() or not MATTER_RE.fullmatch(matter_id):
        errors["matter_id"] = "must look like MAT-1234-56789"

    if errors:
        raise ValidationError(errors)

    return CleanUpload(
        stored_name=uuid.uuid4().hex + "." + ext,
        display_name=display_name,
        extension=ext,
        content_type=CANONICAL_TYPE[ext],
        size_bytes=size,
        matter_id=matter_id,
    )