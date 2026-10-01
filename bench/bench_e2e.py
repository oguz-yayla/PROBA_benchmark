"""
Experiment E4 -- complete election runs (Algorithms 5-8) with n_v voters.

Every voter: generates an election wallet, registers blindly with t_i of n_i
issuers, builds a ballot, authenticates itself to every issuer of its quorum,
pins it in a local IPFS (kubo) node, retrieves and checks the bytes, and
submits (B_v, cid_v, tau_v) from its own zero-balance wallet to the PROBA
contract (zero gas price).  A fraction of voters re-votes after Delta_min.
The auditor reconstructs Latest[.] from the ledger events, recovers every
effective object both from the transaction calldata and from IPFS (and checks
that they are identical), re-runs all checks, verifies |S| <= #receipts,
aggregates, collects t_d verified partial decryptions and compares the tally
with ground truth.
"""
from __future__ import annotations

import os
import random
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bench.common import summarize, save_json, save_raw, environment, tool_version, QUICK  # noqa: E402
from proba import tiac as TIAC, elgamal as HE, ballot as BL, registration as RG, chain as CH  # noqa: E402
from proba.ipfs import IpfsNode  # noqa: E402
from proba.crypto import keccak256  # noqa: E402

NV_LIST = [50, 100] if QUICK else [100, 250, 500, 1000]
NC, NI, TI, ND, TD = 5, 5, 3, 5, 3
REVOTE = 0.2


def run(nv: int, node: CH.Node, art, ipfs: IpfsNode, seed: int):
    rnd = random.Random(seed)
    eid = keccak256(b"E4-%d-%d" % (nv, seed))
    t_cred = 2 ** 40
    ph, per = {}, {k: [] for k in ("register", "reg_voter_cpu", "ballot", "ipfs_add", "ipfs_cat", "submit",
                                   "gas_first", "gas_revote")}

    # ---------------- Algorithm 5: setup
    t0 = time.perf_counter()
    tk, Y = HE.trustee_dkg(eid, ND, TD)
    assert all(HE.verify_key(eid, k.index, k.Y, k.pop) for k in tk)
    keys, mvk = TIAC.keygen_dkg(NI, TI)
    pc = CH.ProbaContract(node, art["ProbaElection"], eid, NC, Y, mvk,
                          [TI, TD, 0, 2 ** 40, 0, 2 ** 40, t_cred, BL.S_MAX, BL.DELTA_MIN])
    ph["setup"] = time.perf_counter() - t0

    # ---------------- Algorithm 6: registration
    idents = [RG.Identity(f"voter-{i}") for i in range(nv)]
    reg, issuers = RG.setup_registration(eid, idents, keys, TI)
    voters = []
    t0 = time.perf_counter()
    for ident in idents:
        w = BL.Wallet.new()
        quorum = rnd.sample(issuers, TI)          # any t_i responsive issuers
        tm = {}
        sigma = RG.register_voter(ident, w, eid, t_cred, reg, quorum, mvk, TI, 1, tm)
        per["register"].append(tm["total"] * 1e3)
        per["reg_voter_cpu"].append((tm["prep"] + tm["auth_voter"] + tm["unblind_total"] + tm["aggregate"]) * 1e3)
        voters.append((w, sigma))
    ph["registration"] = time.perf_counter() - t0
    assert all(v == "issued" for v in reg.state.values())

    # ---------------- Algorithm 7: casting (+ re-votes)
    truth = {}
    archive_cids = {}

    def cast(w, sigma, seq):
        choice = rnd.randrange(NC)
        vote = [0] * NC; vote[choice] = 1
        a = time.perf_counter()
        tx, _ = BL.build_ballot(w, sigma, mvk, Y, eid, t_cred, seq, vote)
        b = time.perf_counter()
        cid_s = ipfs.add(tx.B)
        c = time.perf_counter()
        assert cid_s == BL.cid_string(tx.cid)                  # H_cid == IPFS CIDv1
        assert ipfs.cat(cid_s) == tx.B                          # step 4: verify retrieved bytes
        d = time.perf_counter()
        rc = pc.cast(w, tx)
        e = time.perf_counter()
        assert rc.status == 1
        per["ballot"].append((b - a) * 1e3); per["ipfs_add"].append((c - b) * 1e3)
        per["ipfs_cat"].append((d - c) * 1e3); per["submit"].append((e - d) * 1e3)
        per["gas_first" if seq == 1 else "gas_revote"].append(rc.gasUsed)
        truth[w.pk] = choice
        archive_cids[tx.cid] = cid_s

    t0 = time.perf_counter()
    for w, sigma in voters:
        cast(w, sigma, 1)
    revoters = rnd.sample(voters, int(REVOTE * nv))
    node.w3.provider.make_request("evm_increaseTime", [BL.DELTA_MIN])   # respect Delta_min
    node.w3.provider.make_request("evm_mine", [])
    for w, sigma in revoters:
        cast(w, sigma, 2)
    ph["casting"] = time.perf_counter() - t0
    n_tx = nv + len(revoters)

    # ---------------- Algorithm 8: audit, aggregation, tally
    t0 = time.perf_counter()
    events = pc.accepted_events()
    latest = {}
    for ev in events:                                       # replay the ledger
        a = ev["args"]
        if a.pkHash not in latest or a.seq > latest[a.pkHash][0]:
            latest[a.pkHash] = (a.seq, a.cid, ev["transactionHash"])
    assert len(latest) <= len(reg.receipts)                 # |S| <= number of issuance receipts
    t1 = time.perf_counter()
    auditor = BL.Board(eid, NC, Y, mvk, 0, 2 ** 40)
    effective = []
    fetch_t, ledger_t = [], []
    for pkh, (seq, cid, txh) in latest.items():
        f0 = time.perf_counter()
        B_ledger = pc.c.decode_function_input(node.w3.eth.get_transaction(txh)["input"])[1]["B"]
        f1 = time.perf_counter()
        B = ipfs.cat(BL.cid_string(cid))
        f2 = time.perf_counter()
        assert B == B_ledger and BL.cid_digest(B_ledger) == cid   # ledger copy == IPFS copy
        ledger_t.append((f1 - f0) * 1e3); fetch_t.append((f2 - f1) * 1e3)
        p = BL.parse(B)
        assert keccak256(p.pk) == pkh
        rec = pc.latest(p.pk)
        seq_, v_, tlast_, cid_, r_, s_ = rec                 # Latest[pk] = (seq, v, t_last, cid, r, s)
        assert seq_ == seq and cid_ == cid                   # event log == contract state
        tau = (r_, s_, v_)
        ok, why = auditor.accept(BL.CastTx(B, cid, tau), 10)    # repeat C1-C5
        assert ok, why
        effective.append((p.A, p.Bc))
    t2 = time.perf_counter()
    SA, SB = HE.aggregate(effective)
    t3 = time.perf_counter()
    sub = rnd.sample(tk, TD)
    pub = {k.index: [HE.partial_decrypt(eid, k, SA[j], j) for j in range(NC)] for k in sub}
    t4 = time.perf_counter()
    dlog = HE.DLog(nv)
    result = []
    for j in range(NC):
        parts = {}
        for k in sub:
            d, pf = pub[k.index][j]
            assert HE.verify_partial(eid, k.index, k.Y, SA[j], j, d, pf)
            parts[k.index] = d
        result.append(HE.combine(SB[j], parts, dlog))
    t5 = time.perf_counter()
    expected = [sum(1 for v in truth.values() if v == j) for j in range(NC)]
    assert result == expected, (result, expected)
    ph.update(audit_ledger=t1 - t0, audit_objects=t2 - t1, aggregate=t3 - t2, trustees=t4 - t3,
              combine=t5 - t4, audit_total=t5 - t0)

    gas_total = sum(per["gas_first"]) + sum(per["gas_revote"])
    res = dict(nv=nv, nc=NC, ni=NI, ti=TI, nd=ND, td=TD, revoters=len(revoters), transactions=n_tx,
               effective=len(effective), tally=result, tally_correct=True,
               phase_seconds=ph, per_voter={k: summarize(v) for k, v in per.items() if v},
               audit_fetch=summarize(fetch_t), audit_ledger_fetch=summarize(ledger_t),
               receipts=len(reg.receipts), gas_total=gas_total,
               gas_per_tx=gas_total / n_tx, deploy_gas=pc.deploy_gas)
    print(f"nv={nv:5d} setup {ph['setup']:.2f}s reg {ph['registration']:.2f}s cast {ph['casting']:.2f}s "
          f"audit+tally {ph['audit_total']:.2f}s  tally={result}  gas/tx={res['gas_per_tx']:,.0f}")
    return res, per


def main():
    node = CH.Node()
    ipfs = IpfsNode()
    try:
        art = CH.compile_contracts()
        env = environment(dict(anvil=tool_version([CH.ANVIL, "--version"]), solc=CH.solc_version(),
                               ipfs=f"kubo {ipfs.version()} (offline, localhost)"))
        runs, raw = [], {}
        for i, nv in enumerate(NV_LIST):
            r, per = run(nv, node, art, ipfs, seed=1000 + i)
            runs.append(r)
            for k in ("register", "ballot", "ipfs_add", "ipfs_cat", "submit"):
                raw[f"nv{nv}_{k}"] = per[k]
        save_raw("E4_e2e", raw)
        save_json("E4_e2e", dict(env=env, runs=runs))
    finally:
        ipfs.close()
        node.close()


if __name__ == "__main__":
    main()
