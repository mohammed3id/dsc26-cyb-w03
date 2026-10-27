# dsc26-cyb-w03 · Bayyina document access guard

DSC Summer Internship 2026 · Cybersecurity track · Week 3 (OWASP Top 10, secure coding, authN and authZ)
**Python 3.12 · pytest 9.1.1 · standard library only** · expected time 3 to 4 hours · everything runs offline

## Scenario

Bayyina's platform team is wiring contract upload and review. Before any handler is written, Yasmine
wants the three security pieces as a small, well-tested package the SWE pod can call: upload
validation, the document access policy, and password storage for the firm's local break-glass
accounts. You build `bayyina_guard`. No web framework; the SWE pod wires it in.

## Set up

1. On GitHub create a **public** repository in your own account named exactly `dsc26-cyb-w03`, with no README.
2. Unzip this starter into a folder called `dsc26-cyb-w03`, then:

```bash
git init -b main
uv venv --python 3.12
source .venv/bin/activate            # Windows: .venv\Scripts\activate
uv pip install -r requirements.txt   # pinned versions; you cannot add packages
python -m pytest -q                  # the 5 public tests fail until you build the task
git add . && git commit -m "chore: starter from DSC"
git remote add origin https://github.com/<your-username>/dsc26-cyb-w03.git
git push -u origin main
```

Always run tests with `python -m pytest` from the repository root, the way the grader does.

## Files

```
bayyina_guard/__init__.py
bayyina_guard/validation.py   # part 1
bayyina_guard/policy.py       # part 2
bayyina_guard/passwords.py    # part 3
tests/test_public.py
AI_USAGE.md                   # fill in before you submit (the grader checks the headings)
requirements.txt
```

Keep the names and signatures exactly as they are in the starter: the grader imports them. The
dataclasses and `ValidationError` are already written; the functions raise `NotImplementedError`.

## What to build

### 1. `bayyina_guard/validation.py`

```python
MAX_BYTES = 25 * 1024 * 1024

class ValidationError(Exception):
    def __init__(self, errors: dict[str, str]): ...   # keeps .errors: field name -> message

@dataclass(frozen=True)
class CleanUpload:
    stored_name: str      # "<32 hex chars>.<ext>", generated, never derived from the filename
    display_name: str     # the filename after NFC normalisation
    extension: str        # "pdf" or "docx", lowercase
    content_type: str
    size_bytes: int
    matter_id: str

def validate_upload(meta: dict) -> CleanUpload: ...
```

`meta` has `filename`, `content_type`, `size_bytes`, `matter_id` and `first_bytes` (the first bytes of
the file). Check every field and raise **one** `ValidationError` listing all failing fields (keys
exactly `filename`, `content_type`, `size_bytes`, `matter_id`, `first_bytes`):

- `filename`: a string; NFC-normalise it, then 1–120 characters; no control characters (Unicode
  category `Cc`); none of the bidi controls U+061C, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069; no
  `/`, no `\`, no `..` anywhere; must not start with `.`; the part after the last dot, lowercased, must
  be `pdf` or `docx`, and there must be a non-blank name before that dot. Arabic letters and spaces are
  fine.
- `content_type`: exactly `application/pdf` for pdf,
  `application/vnd.openxmlformats-officedocument.wordprocessingml.document` for docx. (If the filename
  is invalid, only check that it is a string.)
- `first_bytes`: must be `bytes`; for pdf it must start with `b"%PDF-"`, for docx with `b"PK\x03\x04"`.
  (If the filename is invalid, only check that it is `bytes`.)
- `size_bytes`: an `int` (not a `bool`, not a float) from 1 to `MAX_BYTES` inclusive.
- `matter_id`: ASCII only, exactly `MAT-` + 4 digits + `-` + 5 digits, nothing before or after (no
  trailing newline).

On success, `stored_name` is 32 random lowercase hex characters, a dot and the lowercase extension
(for example `uuid.uuid4().hex + ".pdf"`), different on every call; `content_type` is the canonical
type for the extension.

### 2. `bayyina_guard/policy.py`

```python
@dataclass(frozen=True)
class User:
    id: str
    role: str                       # partner | associate | paralegal | client | auditor
    client_id: str | None = None    # for client users: which Bayyina client they belong to
    matters: frozenset[str] = field(default_factory=frozenset)
    mfa: bool = False               # this session passed MFA

@dataclass(frozen=True)
class Document:
    id: str
    client_id: str
    matter_id: str
    confidentiality: str = "normal" # "normal" or "restricted"
    legal_hold: bool = False

@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str

def authorize(user: User | None, action: str, doc: Document) -> Decision: ...
def visible_documents(user: User | None, docs: list[Document]) -> list[Document]: ...
```

Actions: `read`, `comment`, `upload_version`, `delete`, `share_external`. What each role may do at most:

| Role | Actions |
|---|---|
| partner | all five |
| associate | read, comment, upload_version |
| paralegal | read, upload_version |
| client | read, comment |
| auditor | none (auditors read the audit log, which is a different system) |

Evaluate in exactly this order and return the first denial as `Decision(False, "<reason>")`; if none
applies, return `Decision(True, "ok")`:

1. `unauthenticated`: user is `None` or has an empty id.
2. `unknown_action`.
3. `unknown_role`.
4. `legal_hold`: the action is `delete` and the document is on legal hold.
5. `role_not_permitted`: the action is not in the role's list.
6. `tenant_mismatch`: a client user whose `client_id` is `None` or not exactly equal to the document's.
7. `not_assigned`: an associate or paralegal whose `matters` does not contain the document's matter.
8. `restricted`: a client or paralegal and the document is not `normal`.
9. `mfa_required`: the document is not `normal`, or the action is `share_external`, and `user.mfa` is
   not `True`.

"Exactly equal" means exactly: `"CL-A"`, `"cl-a"` and `"CL-A "` are three different tenants. Any
confidentiality value other than `"normal"` counts as not normal.

`visible_documents` returns, in the original order, the documents the user may `read`.

### 3. `bayyina_guard/passwords.py`

```python
def hash_password(password: str) -> str: ...
def verify_password(password: str, stored: str) -> bool: ...
def needs_rehash(stored: str) -> bool: ...
```

- Normalise the password with NFKC, then require 8–128 characters (`ValueError` otherwise; `TypeError`
  if it is not a string).
- Hash with `hashlib.scrypt`, a 16-byte random salt, `n=2**14, r=8, p=5`, `dklen=32`,
  `maxmem=64 * 1024 * 1024`.
- Format: `scrypt$<n>$<r>$<p>$<salt>$<hash>`, salt and hash as URL-safe base64 without `=` padding.
- `verify_password` reads n, r and p from the stored string (so older hashes still verify), but returns
  `False`, never raises, if the string is malformed (including a stored value that is not a string), if
  n is not a power of two between 2 and 2**20, if r is not 1–32 or p not 1–16, if the salt is shorter
  than 16 bytes, if the hash is not exactly 32 bytes, or if scrypt refuses the parameters. Check these
  bounds **before** calling scrypt: a stored string with a huge `p` fits in memory and would run for
  minutes. Compare with `hmac.compare_digest`.
- `needs_rehash` is `True` if the stored string cannot be parsed or any of n, r, p is below the current
  values.

## Public tests

`tests/test_public.py`: an Arabic filename accepted and renamed, all errors reported together, a client
denied another client's contract, an associate on the matter commenting, and a password round trip.
They are a smoke test, not the grade. Each scrypt call takes about a quarter of a second, so do not
loop over thousands of hashes in your own tests.

## How grading works

1. Push, then press **Submit for grading** on DSC Hex. The grader pins your latest commit, clones it,
   copies in DSC's hidden tests and runs
   `python -m pytest -q -p no:cacheprovider --timeout=60 tests_hidden/` from the repository root with
   Python 3.12, the pinned packages and the network off: 60 seconds per test, 4 minutes in total. If the
   whole run passes 4 minutes, no test is credited.
2. Before the run the grader deletes any root `conftest.py`, ignores pytest settings in config files,
   and removes top-level files that would shadow a standard-library or test-tool module. Keep your code
   inside `bayyina_guard/`.
3. If `AI_USAGE.md` is missing or lacks any of the headings `## Tools`, `## What AI got wrong`,
   `## In my own words`, the grader stops and scores 0 with that reason.
4. You get a score from 0 to 100 and, per hidden test, its public name, pass or fail and a short hint.
   Each ID passes only if every case under it passes. A hidden test that cannot import a name fails on
   its own; the others still run. Property tests use fixed seeds, so the same code always gets the
   same score.
5. 5 grader runs per task per day. Late policy: ×1.0 within 72 hours of the W3 session starting, ×0.6
   for the following 7 days, ×0.5 after that until Thu 3 Dec 23:59. W5 reopens W3 at ×1.0.

### Hidden tests

| ID | Public name | What it checks | Weight |
|---|---|---|---|
| H01 | filename: no path tricks | `..\x.pdf`, `/abs.pdf`, `a/b.pdf`, `.hidden.pdf`, `x..pdf`, `x.pdf/` are rejected | 8 |
| H02 | filename: no invisible or control characters | An RLE (U+202B) inside an Arabic name, a NUL, a newline, an isolate (U+2066), an RLO (U+202E), an Arabic letter mark (U+061C) | 8 |
| H03 | filename: the last extension decides | `LEASE.PDF` and `x.exe.pdf` pass; `x.pdf.exe`, `x.`, `pdf`, ` .pdf` fail | 6 |
| H04 | type and signature must agree with the extension | A `.docx` sent as PDF; DOCX type with PDF bytes (a `first_bytes` error, not a `content_type` one); a correct DOCX passes | 8 |
| H05 | size: integers only, inclusive limit | `True`, `10.0`, `0`, `"10"`, `MAX_BYTES + 1` fail; `1` and `MAX_BYTES` pass | 6 |
| H06 | matter id: ASCII, exact, no trailing newline | Arabic-Indic digits, trailing `\n`, leading space, lowercase prefix, wrong digit count | 6 |
| H07 | names: NFC display name, unique generated stored names | A decomposed `café.pdf` is returned in NFC; 50 uploads get 50 different stored names of the form `<32 hex>.pdf` | 4 |
| H08 | policy: deny by default | `None` user, empty id, unknown action, unknown role, auditor | 8 |
| H09 | policy: tenant isolation holds for any input | Property test over client ids (including `cl-a`, `CL-A `, empty, `None`), actions, confidentiality, MFA and legal hold: a client is only ever allowed on an exact, normal match | 8 |
| H10 | policy: assignment, restricted documents and MFA | Associate off-matter, associate on restricted without and with MFA, paralegal comment and restricted, partner sharing without and with MFA | 10 |
| H11 | policy: precedence of reasons | Legal hold beats everything for delete; a client deleting is `role_not_permitted` before `tenant_mismatch`; a client on another tenant's restricted document is `tenant_mismatch`; an unassigned associate on a restricted document is `not_assigned` | 8 |
| H12 | lists go through the same policy | `visible_documents` equals filtering with `authorize(..., "read", ...)` for several users and keeps order | 6 |
| H13 | passwords: random salt, exact format, malformed input is False | Two hashes of one password differ; the prefix is `scrypt$16384$8$5`, 16-byte salt, 32-byte key, no padding; empty, truncated, wrong-scheme, bad base64, non-string and out-of-bounds strings (r, p, n, salt and key length) all return `False`; DoS-sized parameter strings return `False` within 10 seconds | 8 |
| H14 | passwords: normalisation, limits and upgrades | NFC and NFD spellings of `café-مرحبا` verify against each other; 7 and 129 characters raise `ValueError`, bytes raise `TypeError`; a legacy `n=4096, p=1` hash verifies and `needs_rehash` is `True` | 6 |
| | | **Total** | **100** |

**Anti-cheating notes.** H09 is a property test over generated users and documents, so a table of the
public cases fails. H13 includes a hash truncated by four characters: a verifier that lets the stored
string choose the key length compares only a prefix and wrongly says yes. There is nothing to copy from
the public tests that passes the hidden ones.

## AI tools

AI tools are allowed. `AI_USAGE.md` must keep its three headings (`## Tools`, `## What AI got wrong`,
`## In my own words`). Under `## In my own words`, answer in one or two sentences each, without AI:

1. Why does `get_document` return 404 rather than 403 when a client asks for another client's contract?
2. Why must `verify_password` refuse a stored hash that is shorter than 32 bytes, even though the prefix matches?

The grader does not score the content, but it scores 0 if the file or a heading is missing.
Assistants are good at the happy path and weak at exactly what this task tests: a Unicode digit that
`\d` accepts, a stored hash that tells the verifier how many bytes to compare.

## Rules

- Defensive and offline. Standard library only; you cannot add packages.
