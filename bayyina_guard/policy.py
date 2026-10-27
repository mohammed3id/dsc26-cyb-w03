"""Document access policy for Bayyina. Rules: README.md, "What to build", part 2."""
from __future__ import annotations

from dataclasses import dataclass, field


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


def authorize(user: User | None, action: str, doc: Document) -> Decision:
    """Evaluate the nine rules in order and return the first denial, else Decision(True, "ok")."""
    raise NotImplementedError


def visible_documents(user: User | None, docs: list[Document]) -> list[Document]:
    """The documents `user` may read, in their original order."""
    raise NotImplementedError
