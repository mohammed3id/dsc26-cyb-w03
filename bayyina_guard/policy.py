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


ROLE_ACTIONS = {
    "partner": {"read", "comment", "upload_version", "delete", "share_external"},
    "associate": {"read", "comment", "upload_version"},
    "paralegal": {"read", "upload_version"},
    "client": {"read", "comment"},
    "auditor": set(),
}
ALL_ACTIONS = {"read", "comment", "upload_version", "delete", "share_external"}


def authorize(user: User | None, action: str, doc: Document) -> Decision:
    """Evaluate the nine rules in order and return the first denial, else Decision(True, "ok")."""
    # 1. no user, or empty id
    if user is None or not user.id:
        return Decision(False, "unauthenticated")
    # 2. action must be one of the five
    if action not in ALL_ACTIONS:
        return Decision(False, "unknown_action")
    # 3. role must be one of the five
    if user.role not in ROLE_ACTIONS:
        return Decision(False, "unknown_role")
    # 4. nobody may delete a document on legal hold
    if action == "delete" and doc.legal_hold:
        return Decision(False, "legal_hold")
    # 5. the role is never allowed this action
    if action not in ROLE_ACTIONS[user.role]:
        return Decision(False, "role_not_permitted")
    # 6. a client may only touch its own tenant (exact string match)
    if user.role == "client" and (user.client_id is None or user.client_id != doc.client_id):
        return Decision(False, "tenant_mismatch")
    # 7. associates and paralegals only work on their own matters
    if user.role in ("associate", "paralegal") and doc.matter_id not in user.matters:
        return Decision(False, "not_assigned")
    # 8. clients and paralegals never see anything but "normal" documents
    if user.role in ("client", "paralegal") and doc.confidentiality != "normal":
        return Decision(False, "restricted")
    # 9. sensitive documents and external sharing need MFA (exactly True)
    if (doc.confidentiality != "normal" or action == "share_external") and user.mfa is not True:
        return Decision(False, "mfa_required")
    return Decision(True, "ok")


def visible_documents(user: User | None, docs: list[Document]) -> list[Document]:
    """The documents `user` may read, in their original order."""
    return [d for d in docs if authorize(user, "read", d).allowed]