"""Upload validation for Bayyina contracts. Rules: README.md, "What to build", part 1."""
from __future__ import annotations

from dataclasses import dataclass

MAX_BYTES = 25 * 1024 * 1024


class ValidationError(Exception):
    def __init__(self, errors: dict[str, str]):
        super().__init__(", ".join(sorted(errors)))
        self.errors = errors          # field name -> message; keys from: filename, content_type,
                                      # size_bytes, matter_id, first_bytes


@dataclass(frozen=True)
class CleanUpload:
    stored_name: str      # "<32 hex chars>.<ext>", generated, never derived from the filename
    display_name: str     # the filename after NFC normalisation
    extension: str        # "pdf" or "docx", lowercase
    content_type: str
    size_bytes: int
    matter_id: str


def validate_upload(meta: dict) -> CleanUpload:
    """Check every field of `meta` and raise one ValidationError listing all failing fields."""
    raise NotImplementedError
