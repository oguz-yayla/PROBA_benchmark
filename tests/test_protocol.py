"""Correctness and soundness sanity tests for the PROBA v3.4 reference code.

Run:  python -m pytest -q tests/        (the chain test needs anvil + solc)
"""
import os
import shutil
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from proba import tiac as TIAC, elgamal as HE, ballot as BL, registration as RG  # noqa: E402
from proba.crypto import (keccak256, g1, h1, gE, G1, DST_GEN, mul1, msm1, rand_scalar, enc1, dec1,  # noqa: E402
                          enc2, dec2, g2, R, inv, hash_to_scalar, lagrange_at_zero, TAG_ATTR)

EID = keccak256(b"test-election")
TC = 2 ** 40


@pytest.fixture(scope="module")
def setup():
    tk, Y = HE.trustee_dkg(EID, 5, 3)
    keys, mvk = TIAC.keygen_dkg(5, 3)
    return tk, Y, keys, mvk


def cred(w, keys, mvk, subset):
    req, st = TIAC.prepare_issue(EID, w.pk, TC)
    sh = {keys[i].index: TIAC.unblind(TIAC.blind_issue(keys[i], req), st, keys[i].index, mvk) for i in subset}
    return TIAC.aggregate(sh, st, mvk)


def test_encoding_roundtrip():
    P, Q = mul1(g1, rand_scalar()), g2 * TIAC.S(rand_scalar())
    assert dec1(enc1(P)) == P and dec2(enc2(Q)) == Q
    assert 0 <= hash_to_scalar(TAG_ATTR, b"x") < R


def test_bases_are_hash_to_curve():
    """h1 and g_E are nothing-up-my-sleeve points (RFC 9380, published DST)."""
    assert h1 == G1.hash_to_curve(DST_GEN, b"h1") and gE == G1.hash_to_curve(DST_GEN, b"gE")


def test_credential_any_quorum_and_wallet_binding(setup):
    _, _, keys, mvk = setup
    w = BL.Wallet.new()
    for subset in ([0, 1, 2], [2, 3, 4], [0, 2, 4]):
        th = TIAC.prove(cred(w, keys, mvk, subset), mvk, EID, w.pk, TC)
        assert TIAC.verify(mvk, EID, w.pk, TC, th)
        assert not TIAC.verify(mvk, EID, BL.Wallet.new().pk, TC, th)      # bound to pk_v
        assert not TIAC.verify(mvk, EID, w.pk, TC + 1, th)                # bound to T_cred


def test_below_threshold_fails(setup):
    _, _, keys, mvk = setup
    w = BL.Wallet.new()
    req, st = TIAC.prepare_issue(EID, w.pk, TC)
    sh = {keys[i].index: TIAC.unblind(TIAC.blind_issue(keys[i], req), st, keys[i].index, mvk) for i in (0, 1)}
    with pytest.raises(ValueError):
        TIAC.aggregate(sh, st, mvk)


def test_showings_are_rerandomized(setup):
    _, _, keys, mvk = setup
    w = BL.Wallet.new()
    s = cred(w, keys, mvk, [0, 1, 2])
    a, b = TIAC.prove(s, mvk, EID, w.pk, TC), TIAC.prove(s, mvk, EID, w.pk, TC)
    assert a.hp != b.hp and a.sp != b.sp and a.hp != s[0]


def test_pedersen_base_with_known_log_breaks_unforgeability(setup):
    """Documents the specification requirement on h1: if log_g1(h1) is known, two
    identities sharing one commitment C give h^y and credentials on any wallet."""
    _, _, keys, mvk = setup
    t = rand_scalar()
    bad_h1 = mul1(g1, t)
    w1, w2, target = BL.Wallet.new(), BL.Wallet.new(), BL.Wallet.new()
    m1, m2 = TIAC.attr(EID, w1.pk, TC), TIAC.attr(EID, w2.pk, TC)
    o1 = rand_scalar()
    o2 = (o1 + t * (m1 - m2)) % R
    C = msm1([g1, bad_h1], [o1, m1])
    assert C == msm1([g1, bad_h1], [o2, m2])                       # one C, two openings
    h = TIAC.H1(C)
    lag = lagrange_at_zero([k.index for k in keys[:3]])
    sig = lambda m: msm1([h] * 3, [(lag[i] * (keys[i].x + keys[i].y * m)) % R for i in range(3)])
    s1, s2 = sig(m1), sig(m2)                                       # honestly issued under the same h
    hy = mul1(s1 + (-s2), inv((m1 - m2) % R))
    mt = TIAC.attr(EID, target.pk, TC)
    assert TIAC.verify(mvk, EID, target.pk, TC, TIAC.Showing(h, s1 + mul1(hy, (mt - m1) % R)))


def _reg(keys, ids, t_i=3, t_open=0, t_close=10):
    idents = [RG.Identity(i) for i in ids]
    reg, iss = RG.setup_registration(EID, idents, keys, t_i, t_open, t_close)
    return {v.ID: v for v in idents}, reg, iss


def test_registration_state_machine(setup):
    _, _, keys, mvk = setup
    idv, reg, iss = _reg(keys, ["a", "c"])
    RG.register_voter(idv["a"], BL.Wallet.new(), EID, TC, reg, iss, mvk, 3, 5)
    with pytest.raises(PermissionError):
        RG.register_voter(idv["a"], BL.Wallet.new(), EID, TC, reg, iss, mvk, 3, 5)   # identity reuse
    with pytest.raises(PermissionError):
        RG.register_voter(RG.Identity("b"), BL.Wallet.new(), EID, TC, reg, iss, mvk, 3, 5)   # ineligible
    with pytest.raises(PermissionError):
        RG.register_voter(idv["c"], BL.Wallet.new(), EID, TC, reg, iss, mvk, 3, 50)  # outside window


def test_malicious_registrar_cannot_mint_for_abstainer(setup):
    """The registrar issues a valid token for an abstaining identity but cannot
    answer the issuers' independent authentication challenges."""
    _, _, keys, mvk = setup
    idv, reg, iss = _reg(keys, ["abstainer"])
    w = BL.Wallet.new()
    req, st = TIAC.prepare_issue(EID, w.pk, TC)
    rid, hreq, token = reg.authorize("abstainer", req, 5)
    impostor = RG.Identity("abstainer")                             # lacks the real authentication key
    for i in iss:
        nonce = i.challenge("abstainer")
        with pytest.raises(Exception):
            i.issue(req, rid, hreq, token, "abstainer", impostor.respond(EID, i.key.index, nonce, hreq))
    assert not reg.shares[rid]


def test_issuer_local_record_blocks_second_share(setup):
    """Even if the registration state is reset, an honest issuer returns at most
    one share per identity."""
    _, _, keys, mvk = setup
    idv, reg, iss = _reg(keys, ["a"])
    RG.register_voter(idv["a"], BL.Wallet.new(), EID, TC, reg, iss, mvk, 3, 5)
    reg.state["a"] = "unused"                                       # misbehaving registration service
    with pytest.raises(PermissionError):
        RG.register_voter(idv["a"], BL.Wallet.new(), EID, TC, reg, iss[:3], mvk, 3, 5)


def test_release_only_without_returned_shares(setup):
    _, _, keys, mvk = setup
    idv, reg, iss = _reg(keys, ["a", "b"])
    req, st = TIAC.prepare_issue(EID, BL.Wallet.new().pk, TC)
    rid, hreq, tok = reg.authorize("a", req, 5)
    reg.release(rid)                                                # no share returned: allowed
    assert reg.state["a"] == "unused"
    rid, hreq, tok = reg.authorize("b", req, 5)
    n = iss[0].challenge("b")
    iss[0].issue(req, rid, hreq, tok, "b", idv["b"].respond(EID, iss[0].key.index, n, hreq))
    with pytest.raises(PermissionError):
        reg.release(rid)                                            # a share exists: refused


def test_accept_rate_limit_revote_and_tally(setup):
    tk, Y, keys, mvk = setup
    board = BL.Board(EID, 4, Y, mvk, 0, 10 ** 6, s_max=3, delta_min=60)
    ws = []
    for i in range(6):
        w = BL.Wallet.new(); s = cred(w, keys, mvk, [0, 1, 2]); ws.append((w, s))
        v = [0] * 4; v[i % 4] = 1
        assert board.accept(BL.build_ballot(w, s, mvk, Y, EID, TC, 1, v)[0], 100)[0]
    w, s = ws[0]
    tx2, _ = BL.build_ballot(w, s, mvk, Y, EID, TC, 2, [0, 0, 0, 1])
    assert board.accept(tx2, 130) == (False, "C5:interval")
    assert board.accept(tx2, 160)[0]
    assert not board.accept(tx2, 400)[0]                            # replay
    tx4, _ = BL.build_ballot(w, s, mvk, Y, EID, TC, 4, [0, 0, 1, 0])
    assert board.accept(tx4, 400) == (False, "C5:sequence")         # above S_max = 3
    eff = [(BL.parse(r[3]).A, BL.parse(r[3]).Bc) for r in board.latest.values()]
    SA, SB = HE.aggregate(eff)
    dl = HE.DLog(10)
    res = [HE.combine(SB[j], {k.index: HE.pardec_only(k, SA[j]) for k in tk[1:4]}, dl) for j in range(4)]
    assert res == [1, 2, 1, 2]


def test_object_size():
    assert BL.object_size(5) == 512 + 384 * 5 == len(BL.a_bytes(b"\0" * 32, b"\0" * 64, 0, 0, 5, b"\0" * 1280, b"\0" * 704)) + 256


def test_cid_matches_ipfs_format():
    assert BL.cid_string(b"\x00" * 32).startswith("bafkrei")


def test_fallback_wallet_backend_is_bit_exact():
    """The cryptography-based fallback must agree with libsecp256k1 / ecrecover."""
    from proba import secp256k1_fallback as fb
    coincurve = pytest.importorskip("coincurve")
    for _ in range(50):
        k = fb.PrivateKey()
        d = os.urandom(32)
        ck = coincurve.PrivateKey(k.secret)
        assert ck.public_key.format(compressed=False)[1:] == k.pk
        r, s, rec = k.sign_recoverable(d)
        pub = coincurve.PublicKey.from_signature_and_message(r + s + bytes([rec]), d, hasher=None)
        assert pub.format(compressed=False)[1:] == k.pk
        sig = ck.sign_recoverable(d, hasher=None)
        assert fb.recover(d, int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big"), sig[64]) == k.pk


@pytest.mark.skipif(not (shutil.which("anvil") or os.path.exists(os.path.expanduser("~/.proba-tools/bin/anvil"))
                         or os.path.exists("/opt/foundry/anvil")), reason="anvil missing")
def test_contract_agrees_with_python():
    from bench.bench_contract import negative_tests
    from proba import chain as CH
    node = CH.Node()
    try:
        rows = negative_tests(node, CH.compile_contracts())
        assert all(r["passed"] and r["agree"] for r in rows)
    finally:
        node.close()
