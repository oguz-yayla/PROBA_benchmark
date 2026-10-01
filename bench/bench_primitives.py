"""
Experiment E1 -- primitive-level CPU microbenchmarks for PROBA v3.4.

Every operation of Algorithms 5-8 that runs on a CPU is timed individually on
the BLS12-381 instantiation of Section 3.3 (the ElGamal timings therefore
replace the legacy 4096-bit finite-field numbers).  Default parameters:
n_i = 5, t_i = 3 issuers; n_d = 5, t_d = 3 trustees; n_c = 5 candidates.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bench.common import measure, summarize, save_raw, save_json, environment, reps  # noqa: E402
from proba import tiac as TIAC, elgamal as HE, ballot as BL, registration as RG  # noqa: E402
from proba.crypto import keccak256, rand_scalar, gE, mul1, R  # noqa: E402

NI, TI, ND, TD, NC = 5, 3, 5, 3, 5
N_FAST, N_MED, N_SLOW = 500, 200, 30


def main():
    eid = keccak256(b"PROBA-bench-E1")
    t_cred = 2 ** 40
    tk, Y = HE.trustee_dkg(eid, ND, TD)
    keys, mvk = TIAC.keygen_dkg(NI, TI)
    w = BL.Wallet.new()
    m = TIAC.attr(eid, w.pk, t_cred)
    req, st = TIAC.prepare_issue(eid, w.pk, t_cred)
    share = TIAC.blind_issue(keys[0], req)
    shares = {k.index: TIAC.unblind(TIAC.blind_issue(k, req), st, k.index, mvk) for k in keys[:TI]}
    sigma = TIAC.aggregate(shares, st, mvk)
    th = TIAC.prove(sigma, mvk, eid, w.pk, t_cred)
    assert TIAC.verify(mvk, eid, w.pk, t_cred, th)

    vote = [0] * NC; vote[2] = 1
    eb = HE.encrypt(Y, vote)
    prefix = HE.ctx_prefix(eid, w.pk, 1, eb.ct_bytes())
    p01 = HE.prove_01(prefix, 2, Y, eb.A[2], eb.B[2], 1, eb.r[2])
    SA, SB = HE._sum(eb.A), HE._sum(eb.B)
    psum = HE.prove_sum(prefix, Y, SA, SB, sum(eb.r) % R)
    d, pdec = HE.partial_decrypt(eid, tk[0], SA[0] if isinstance(SA, list) else SA, 0)
    dlog = HE.DLog(10_000)
    parts = {k.index: HE.pardec_only(k, SA) for k in tk[:TD]}

    tx, _ = BL.build_ballot(w, sigma, mvk, Y, eid, t_cred, 1, vote)
    idents = [RG.Identity(f"id{i}") for i in range(3000)]
    reg, issuers = RG.setup_registration(eid, idents, keys, TI)
    issuer = issuers[0]
    ctr = iter(range(10 ** 9))

    def fresh_request():
        v = idents[next(ctr)]
        rid, hreq, tok = reg.authorize(v.ID, req, 1)
        nonce = issuer.challenge(v.ID)
        return v, rid, hreq, tok, v.respond(eid, issuer.key.index, nonce, hreq), nonce

    def issuer_checks(a):
        """Identity authentication + token + record/state checks (without BlindIssue)."""
        v, rid, hreq, tok, resp, nonce = a
        issuer.enrolment[v.ID].verify(resp, eid + (issuer.key.index).to_bytes(32, "big") + nonce + hreq)
        reg.token_pk.verify(tok, eid + rid + hreq + RG.hid(v.ID))
        assert keccak256(req.to_bytes()) == hreq
        assert v.ID not in issuer.issued_ids and reg.is_pending(rid) and reg.req_of[rid] == v.ID

    nonce0 = os.urandom(32)
    hreq0 = keccak256(req.to_bytes())

    ops = [
        # --- TIAC / registration (Algorithm 6)
        ("TIAC", "T_Hattr", "Attribute hash m_v = H_attr(eid, pk, T_cred)", lambda: TIAC.attr(eid, w.pk, t_cred), None, N_FAST),
        ("TIAC", "T_Prep", "PrepareIssue incl. pi_iss", lambda: TIAC.prepare_issue(eid, w.pk, t_cred), None, N_MED),
        ("TIAC", "T_ReqVer", "Verify pi_iss (issuer side, incl. H1)", lambda: TIAC.verify_issue_request(req), None, N_MED),
        ("TIAC", "T_Issue", "BlindIssue incl. pi_iss verification", lambda: TIAC.blind_issue(keys[0], req), None, N_MED),
        ("TIAC", "T_Unblind", "Unblind one share incl. pairing check", lambda: TIAC.unblind(share, st, 1, mvk), None, N_MED),
        ("TIAC", "T_AggCred", f"Aggregate t_i={TI} shares incl. verification", lambda: TIAC.aggregate(shares, st, mvk), None, N_MED),
        ("TIAC", "T_PrCred", "Show credential (re-randomisation)", lambda: TIAC.prove(sigma, mvk, eid, w.pk, t_cred), None, N_FAST),
        ("TIAC", "T_VrCred", "Verify credential showing (C3)", lambda: TIAC.verify(mvk, eid, w.pk, t_cred, th), None, N_MED),
        ("Registration", "T_Auth", "Registrar: window/eligibility, RegDB unused->pending, token", None, None, N_MED),
        ("Registration", "T_IdResp", "Voter: identity-authentication response to one issuer", lambda: idents[0].respond(eid, 1, nonce0, hreq0), None, N_FAST),
        ("Registration", "T_IssChk", "Issuer: identity authentication, token, record and state checks", None, None, N_MED),
        # --- ElGamal / Chaum--Pedersen (Algorithms 7-8), per candidate unless stated
        ("ElGamal", "T_Enc", "Encrypt one candidate slot", lambda: HE.encrypt(Y, [1]), None, N_FAST),
        ("ElGamal", "T_ParDec", "Partial decryption of one slot", lambda: HE.pardec_only(tk[0], SA), None, N_FAST),
        ("ElGamal", "T_Comb", f"Combine t_d={TD} shares + BSGS (bound 10^4)", lambda: HE.combine(SB, parts, dlog), None, N_MED),
        ("Chaum-Pedersen", "T_PrVV", "Prove 0/1 validity of one slot", lambda: HE.prove_01(prefix, 2, Y, eb.A[2], eb.B[2], 1, eb.r[2]), None, N_MED),
        ("Chaum-Pedersen", "T_VrVV", "Verify 0/1 validity of one slot", lambda: HE.verify_01(prefix, 2, Y, eb.A[2], eb.B[2], p01), None, N_MED),
        ("Chaum-Pedersen", "T_PrVS", "Prove one-selection constraint", lambda: HE.prove_sum(prefix, Y, SA, SB, sum(eb.r) % R), None, N_MED),
        ("Chaum-Pedersen", "T_VrVS", "Verify one-selection constraint", lambda: HE.verify_sum(prefix, Y, SA, SB, psum), None, N_MED),
        ("Chaum-Pedersen", "T_PrCD", "Prove correct partial decryption", lambda: HE.prove_dec(eid, tk[0], SA, 0, d), None, N_MED),
        ("Chaum-Pedersen", "T_VrCD", "Verify correct partial decryption", lambda: HE.verify_partial(eid, 1, tk[0].Y, SA, 0, d, pdec), None, N_MED),
        ("ElGamal", "T_Chal", "Benaloh audit of one slot (re-encryption)", lambda: HE.benaloh_audit(Y, HE.EncBallot([eb.A[2]], [eb.B[2]], [eb.r[2]]), [1]), None, N_MED),
        # --- wallet, hashing, encoding
        ("Wallet/encoding", "T_Sign", "Wallet signature tau_v (secp256k1, EIP-191)", lambda: BL.sign(w, eid, 1, tx.cid), None, N_FAST),
        ("Wallet/encoding", "T_SigVr", "Wallet signature verification (ecrecover)", lambda: BL.verify_sig(w.pk, eid, 1, tx.cid, tx.tau), None, N_FAST),
        ("Wallet/encoding", "T_CID", f"Content identifier H_cid(B_v) (n_c={NC})", lambda: BL.cid_digest(tx.B), None, N_FAST),
        ("Wallet/encoding", "T_Parse", f"Decode B_v incl. subgroup checks (n_c={NC})", lambda: BL.parse(tx.B), None, N_MED),
        # --- composite (n_c = 5)
        ("Composite", "T_Voter", f"Complete ballot preparation (Alg. 7, steps 1,3-5), n_c={NC}",
         lambda: BL.build_ballot(w, sigma, mvk, Y, eid, t_cred, 1, vote), None, N_MED),
        ("Composite", "T_Accept", f"Complete off-chain Accept C1-C5 (Python), n_c={NC}",
         None, None, N_MED),
        # --- setup (Algorithm 5)
        ("Setup", "T_DKG_HE", f"Trustee DKG + key-possession proofs (n_d={ND}, t_d={TD})", lambda: HE.trustee_dkg(eid, ND, TD), None, N_SLOW),
        ("Setup", "T_DKG_TIAC", f"Issuer DKG with Feldman checks (n_i={NI}, t_i={TI})", lambda: TIAC.keygen_dkg(NI, TI), None, N_SLOW),
    ]

    raw, summary = {}, []
    for grp, sym, label, fn, setup, n in ops:
        if sym == "T_Auth":
            samples = measure(lambda: reg.authorize(idents[next(ctr)].ID, req, 1), n)
        elif sym == "T_IssChk":
            samples = measure(issuer_checks, n, setup=fresh_request)
        elif sym == "T_Accept":
            def fresh_board():
                return BL.Board(eid, NC, Y, mvk, 0, 2 ** 41)
            samples = measure(lambda b: b.accept(tx, 10), n, setup=fresh_board)
        else:
            samples = measure(fn, n)
        raw[sym] = samples
        s = summarize(samples)
        s.update(group=grp, symbol=sym, label=label)
        summary.append(s)
        print(f"{sym:12s} {s['mean']:9.4f} ms  (sd {s['sd']:.4f}, median {s['median']:.4f}, n={s['n']})  {label}")

    save_raw("E1_primitives", raw)
    save_json("E1_primitives", dict(env=environment(), params=dict(ni=NI, ti=TI, nd=ND, td=TD, nc=NC),
                                    ballot_bytes=len(tx.B), results=summary))


if __name__ == "__main__":
    main()
