"""
Experiment E2 -- scaling of the per-role CPU cost in the protocol parameters.

 (a) number of candidates n_c : voter ballot preparation (Alg. 7 voter side),
     complete off-chain acceptance C1-C5, object size;
 (b) issuance threshold t_i    : complete registration of one voter (Alg. 6);
 (c) decryption threshold t_d  : trustee work and auditor verification of the
     tally for n_c = 5 (Alg. 8, steps 5-7).
"""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bench.common import measure, summarize, save_raw, save_json, environment, reps  # noqa: E402
from proba import tiac as TIAC, elgamal as HE, ballot as BL, registration as RG  # noqa: E402
from proba.crypto import keccak256  # noqa: E402

NC_LIST = [2, 3, 4, 5, 6, 8, 10]
TI_LIST = [(3, 2), (5, 3), (7, 4), (9, 5), (11, 6), (15, 8)]
TD_LIST = [(3, 2), (5, 3), (7, 4), (9, 5), (11, 6)]


def scale_nc(eid, t_cred, raw):
    tk, Y = HE.trustee_dkg(eid, 5, 3)
    keys, mvk = TIAC.keygen_dealer(5, 3)
    w = BL.Wallet.new()
    req, st = TIAC.prepare_issue(eid, w.pk, t_cred)
    sh = {k.index: TIAC.unblind(TIAC.blind_issue(k, req), st, k.index, mvk) for k in keys[:3]}
    sigma = TIAC.aggregate(sh, st, mvk)
    # Interleaved (round-robin) sampling: every round times every n_c once, so
    # transient load on the shared vCPU is spread evenly over all configurations.
    txs, ws = {}, {}
    for nc in NC_LIST:
        vote = [0] * nc; vote[0] = 1
        ws[nc] = vote
        txs[nc] = BL.build_ballot(w, sigma, mvk, Y, eid, t_cred, 1, vote)[0]
    tv = {nc: [] for nc in NC_LIST}
    ta = {nc: [] for nc in NC_LIST}
    n = reps(150)
    for rnd in range(n + 3):
        for nc in NC_LIST:
            a = time.perf_counter_ns()
            BL.build_ballot(w, sigma, mvk, Y, eid, t_cred, 1, ws[nc])
            b = time.perf_counter_ns()
            board = BL.Board(eid, nc, Y, mvk, 0, 2 ** 41)
            c = time.perf_counter_ns()
            ok, _ = board.accept(txs[nc], 10)
            d = time.perf_counter_ns()
            assert ok
            if rnd >= 3:
                tv[nc].append((b - a) / 1e6); ta[nc].append((d - c) / 1e6)
    out = []
    for nc in NC_LIST:
        raw[f"voter_nc{nc}"], raw[f"accept_nc{nc}"] = tv[nc], ta[nc]
        r = dict(nc=nc, voter=summarize(tv[nc]), accept=summarize(ta[nc]), wire_bytes=len(txs[nc].B),
                 compressed_bytes=BL.compressed_size(nc))
        out.append(r)
        print(f"nc={nc:2d} voter median {r['voter']['median']:7.2f} ms  accept median {r['accept']['median']:7.2f} ms  |B_v|={len(txs[nc].B)} B")
    return out


def scale_ti(eid, t_cred, raw):
    ctx = {}
    n = reps(80)
    idents = [RG.Identity(f"id{i}") for i in range(n + 3)]
    for ni, ti in TI_LIST:
        keys, mvk = TIAC.keygen_dealer(ni, ti)
        reg, issuers = RG.setup_registration(eid, idents, keys, ti)
        ctx[ti] = (ni, mvk, reg, issuers,
                   {k: [] for k in ("prep", "authorize", "auth_voter", "issue_total", "unblind_total", "aggregate", "total")})
    for rnd in range(n + 3):
        for ni, ti in TI_LIST:
            _, mvk, reg, issuers, parts = ctx[ti]
            tm = {}
            RG.register_voter(idents[rnd], BL.Wallet.new(), eid, t_cred, reg, issuers, mvk, ti, 1, tm)
            if rnd >= 3:
                for k in parts:
                    parts[k].append(tm[k] * 1e3)
    out = []
    for ni, ti in TI_LIST:
        parts = ctx[ti][4]
        raw[f"reg_ti{ti}"] = parts["total"]
        r = dict(ni=ni, ti=ti, **{k: summarize(v) for k, v in parts.items()})
        voter = [p + r + u + a for p, r, u, a in zip(parts["prep"], parts["auth_voter"], parts["unblind_total"], parts["aggregate"])]
        r["voter_cpu"] = summarize(voter)
        r["issuer_cpu_per_issuer"] = summarize([x / ti for x in parts["issue_total"]])
        out.append(r)
        print(f"(ni,ti)=({ni},{ti}) total median {r['total']['median']:7.2f} ms  voter median {r['voter_cpu']['median']:6.2f} ms")
    return out


def scale_td(eid, raw):
    nc = 5
    out = []
    for nd, td in TD_LIST:
        tk, Y = HE.trustee_dkg(eid, nd, td)
        vote = [1, 0, 0, 0, 0]
        ballots = [HE.encrypt(Y, vote) for _ in range(20)]
        SA, SB = HE.aggregate([(b.A, b.B) for b in ballots])
        dlog = HE.DLog(10_000)
        sub = tk[:td]
        trustee_t, audit_t = [], []
        n = reps(30)
        for rep in range(n + 2):
            t0 = time.perf_counter()
            pub = {}
            for k in sub:   # trustee k: nc partial decryptions with proofs
                pub[k.index] = [HE.partial_decrypt(eid, k, SA[j], j) for j in range(nc)]
            t1 = time.perf_counter()
            res = []
            for j in range(nc):   # auditor: verify every share, combine, recover tally
                parts = {}
                for k in sub:
                    d, pf = pub[k.index][j]
                    assert HE.verify_partial(eid, k.index, k.Y, SA[j], j, d, pf)
                    parts[k.index] = d
                res.append(HE.combine(SB[j], parts, dlog))
            t2 = time.perf_counter()
            assert res == [20, 0, 0, 0, 0]
            if rep >= 2:
                trustee_t.append((t1 - t0) * 1e3 / td)   # per trustee
                audit_t.append((t2 - t1) * 1e3)
        raw[f"tally_trustee_td{td}"], raw[f"tally_audit_td{td}"] = trustee_t, audit_t
        r = dict(nd=nd, td=td, nc=nc, trustee=summarize(trustee_t), audit=summarize(audit_t))
        out.append(r)
        print(f"(nd,td)=({nd},{td}) per-trustee {r['trustee']['mean']:6.2f} ms  audit {r['audit']['mean']:6.2f} ms")
    return out


def main():
    eid = keccak256(b"PROBA-bench-E2")
    t_cred = 2 ** 40
    raw = {}
    res = dict(env=environment(), nc=scale_nc(eid, t_cred, raw), ti=scale_ti(eid, t_cred, raw),
               td=scale_td(eid, raw))
    save_raw("E2_scaling", raw)
    save_json("E2_scaling", res)


if __name__ == "__main__":
    main()
