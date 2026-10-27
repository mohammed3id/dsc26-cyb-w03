import itertools
import pytest
from bayyina_guard.policy import Decision, Document, User, authorize, visible_documents

MATTER = "MAT-2026-00001"
ACTIONS = ["read", "comment", "upload_version", "delete", "share_external"]


def doc(**kw):
    base = dict(id="d1", client_id="CL-A", matter_id=MATTER)
    base.update(kw)
    return Document(**base)


def user(role, **kw):
    base = dict(id="u1", role=role, client_id="CL-A", matters=frozenset({MATTER}), mfa=True)
    base.update(kw)
    return User(**base)


def deny(reason):
    return Decision(False, reason)


# 1 ---- unauthenticated, unknown action, unknown role (rules 1-3, in order)
def test_unauthenticated():
    assert authorize(None, "read", doc()) == deny("unauthenticated")
    assert authorize(user("partner", id=""), "read", doc()) == deny("unauthenticated")


def test_unauthenticated_beats_unknown_action():
    assert authorize(None, "burn", doc()) == deny("unauthenticated")


def test_unknown_action_and_role():
    assert authorize(user("partner"), "burn", doc()) == deny("unknown_action")
    assert authorize(user("intern"), "read", doc()) == deny("unknown_role")
    assert authorize(user("Partner"), "read", doc()) == deny("unknown_role")   # exact match only
    assert authorize(user("intern"), "burn", doc()) == deny("unknown_action")  # action is checked first


# 2 ---- what each role may do at most (rule 5), on a "friendly" document
ALLOWED = {
    "partner": {"read", "comment", "upload_version", "delete", "share_external"},
    "associate": {"read", "comment", "upload_version"},
    "paralegal": {"read", "upload_version"},
    "client": {"read", "comment"},
    "auditor": set(),
}


@pytest.mark.parametrize("role,action", list(itertools.product(ALLOWED, ACTIONS)))
def test_role_matrix(role, action):
    d = authorize(user(role), action, doc())
    if action in ALLOWED[role]:
        assert d == Decision(True, "ok")
    else:
        assert d == deny("role_not_permitted")


# 3 ---- legal hold (rule 4)
def test_legal_hold_blocks_delete_for_everyone():
    held = doc(legal_hold=True)
    assert authorize(user("partner"), "delete", held) == deny("legal_hold")
    assert authorize(user("client"), "delete", held) == deny("legal_hold")   # beats role_not_permitted
    assert authorize(user("auditor"), "delete", held) == deny("legal_hold")


def test_legal_hold_does_not_block_other_actions():
    assert authorize(user("partner"), "read", doc(legal_hold=True)).allowed


# 4 ---- tenant isolation (rule 6)
@pytest.mark.parametrize("cid", ["cl-a", "CL-A ", " CL-A", "", None, "CL-B"])
def test_client_tenant_must_match_exactly(cid):
    assert authorize(user("client", client_id=cid), "read", doc()) == deny("tenant_mismatch")


def test_client_exact_tenant_is_allowed():
    assert authorize(user("client", client_id="CL-A"), "read", doc()).allowed


def test_role_not_permitted_beats_tenant_mismatch():
    other = user("client", client_id="CL-B")
    assert authorize(other, "delete", doc()) == deny("role_not_permitted")


def test_tenant_mismatch_beats_restricted():
    other = user("client", client_id="CL-B")
    assert authorize(other, "read", doc(confidentiality="restricted")) == deny("tenant_mismatch")


# 5 ---- assignment (rule 7)
@pytest.mark.parametrize("role", ["associate", "paralegal"])
def test_off_matter_staff_are_denied(role):
    assert authorize(user(role, matters=frozenset()), "read", doc()) == deny("not_assigned")
    assert authorize(user(role, matters=frozenset({"MAT-2026-99999"})), "read", doc()) == deny("not_assigned")


def test_partner_needs_no_assignment():
    assert authorize(user("partner", matters=frozenset()), "read", doc()).allowed


def test_not_assigned_beats_restricted_and_mfa():
    u = user("associate", matters=frozenset(), mfa=False)
    assert authorize(u, "read", doc(confidentiality="restricted")) == deny("not_assigned")


# 6 ---- restricted documents (rule 8)
def test_client_and_paralegal_never_see_restricted():
    r = doc(confidentiality="restricted")
    assert authorize(user("client"), "read", r) == deny("restricted")        # even with MFA
    assert authorize(user("paralegal"), "read", r) == deny("restricted")


@pytest.mark.parametrize("value", ["restricted", "secret", "", "Normal", "NORMAL", None])
def test_anything_but_exactly_normal_counts_as_not_normal(value):
    assert authorize(user("client"), "read", doc(confidentiality=value)) == deny("restricted")


# 7 ---- MFA (rule 9)
def test_associate_on_restricted_needs_mfa():
    r = doc(confidentiality="restricted")
    assert authorize(user("associate", mfa=False), "read", r) == deny("mfa_required")
    assert authorize(user("associate", mfa=True), "read", r) == Decision(True, "ok")


def test_partner_share_external_needs_mfa():
    assert authorize(user("partner", mfa=False), "share_external", doc()) == deny("mfa_required")
    assert authorize(user("partner", mfa=True), "share_external", doc()) == Decision(True, "ok")


def test_partner_on_restricted_needs_mfa():
    r = doc(confidentiality="restricted")
    assert authorize(user("partner", mfa=False), "read", r) == deny("mfa_required")


def test_mfa_must_be_exactly_true():
    assert authorize(user("partner", mfa=1), "share_external", doc()) == deny("mfa_required")


def test_associate_cannot_share_external():
    assert authorize(user("associate"), "share_external", doc()) == deny("role_not_permitted")


# 8 ---- a small "property" test: a client is allowed ONLY on an exact, normal match
def test_client_allowed_only_on_exact_normal_match():
    tenants = ["CL-A", "cl-a", "CL-A ", "", None, "CL-B"]
    confs = ["normal", "restricted", "", "Normal"]
    for cid, action, conf, mfa, hold in itertools.product(
        tenants, ACTIONS, confs, [True, False], [True, False]
    ):
        d = authorize(user("client", client_id=cid, mfa=mfa), action, doc(confidentiality=conf, legal_hold=hold))
        if d.allowed:
            assert cid == "CL-A" and conf == "normal" and action in ("read", "comment")


# 9 ---- lists go through the same policy
def test_visible_documents_filters_and_keeps_order():
    docs = [
        doc(id="d1"),
        doc(id="d2", client_id="CL-B"),
        doc(id="d3", confidentiality="restricted"),
        doc(id="d4"),
        doc(id="d5", client_id="cl-a"),
    ]
    c = user("client", client_id="CL-A")
    assert [d.id for d in visible_documents(c, docs)] == ["d1", "d4"]
    assert visible_documents(None, docs) == []
    for u in (c, user("partner"), user("associate"), user("paralegal"), user("auditor")):
        assert visible_documents(u, docs) == [d for d in docs if authorize(u, "read", d).allowed]