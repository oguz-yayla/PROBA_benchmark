"""
Experiment E3 -- smart-contract cost of Algorithm 7 (C1-C5) on an
EIP-2537 (Prague) EVM, the Perez--Ceesay baseline (Algorithm 4), and
differential negative tests (Python acceptance predicate vs. contract).
"""
from __future__ import annotations

import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bench.common import summarize, save_json, save_raw, environment, tool_version, reps, QUICK  # noqa: E402
from proba import tiac as TIAC, elgamal as HE, ballot as BL, chain as CH  # noqa: E402
from proba.crypto import keccak256, R, G1, rand_scalar, mul1, g1, enc1  # noqa: E402

NC_LIST = [2, 3, 4, 5, 6, 8, 10]
VOTERS_PER_NC = 3 if QUICK else 8
GAS_LIMITS = [30_000_000, 60_000_000, 100_000_000]
BLOCK_PERIOD_S = 2  # Besu IBFT 2.0 default `blockperiodseconds`
S_MAX, DELTA_MIN = BL.S_MAX, BL.DELTA_MIN


def cfg(t_cred, s_max=S_MAX, delta=DELTA_MIN):
    return [3, 3, 0, 2 ** 40, 0, 2 ** 40, t_cred, s_max, delta]


def advance(node, seconds):
    node.w3.provider.make_request("evm_increaseTime", [seconds])
    node.w3.provider.make_request("evm_mine", [])


def calldata_gas(data: bytes):
    z = data.count(0)
    nz = len(data) - z
    return dict(bytes=len(data), zero=z, nonzero=nz, standard=4 * z + 16 * nz, floor_tokens=z + 4 * nz)


def credential(eid, w, t_cred, keys, mvk, ti=3):
    req, st = TIAC.prepare_issue(eid, w.pk, t_cred)
    sh = {k.index: TIAC.unblind(TIAC.blind_issue(k, req), st, k.index, mvk) for k in keys[:ti]}
    return TIAC.aggregate(sh, st, mvk)


def gas_vs_nc(node, art):
    t_cred = 2 ** 40
    out = []
    for nc in NC_LIST:
        eid = keccak256(b"E3-%d" % nc)
        tk, Y = HE.trustee_dkg(eid, 5, 3)
        keys, mvk = TIAC.keygen_dealer(5, 3)
        pc = CH.ProbaContract(node, art["ProbaElection"], eid, nc, Y, mvk, cfg(t_cred))
        first, revote, prof, cd = [], [], [], []
        for _ in range(VOTERS_PER_NC):
            w = BL.Wallet.new()
            sigma = credential(eid, w, t_cred, keys, mvk)
            vote = [0] * nc; vote[0] = 1
            tx, _ = BL.build_ballot(w, sigma, mvk, Y, eid, t_cred, 1, vote)
            rc = pc.cast(w, tx)
            assert rc.status == 1
            first.append(rc.gasUsed)
            inp = node.w3.eth.get_transaction(rc.transactionHash)["input"]
            cd.append(calldata_gas(bytes(inp)))
            vote2 = [0] * nc; vote2[-1] = 1
            advance(node, DELTA_MIN)
            tx2, _ = BL.build_ballot(w, sigma, mvk, Y, eid, t_cred, 2, vote2)
            rc2 = pc.cast(w, tx2)
            assert rc2.status == 1
            revote.append(rc2.gasUsed)
            # profiled run on a third sequence number (same code path + one event)
            advance(node, DELTA_MIN)
            tx3, _ = BL.build_ballot(w, sigma, mvk, Y, eid, t_cred, 3, vote)
            rc3 = pc.cast(w, tx3, profiled=True)
            prof.append(pc.profile(rc3))
        # breakdown of a *first* vote: C5 store of the profiled (update) run is replaced
        # by the measured first-vote residual so that the parts add up to `first`.
        mean = lambda xs: statistics.fmean(xs)
        pr = {k: mean([p[k] for p in prof]) for k in ("c1", "c2", "c3", "c4", "c5")}
        cdg = mean([c["standard"] for c in cd])
        r = dict(nc=nc, deploy_gas=pc.deploy_gas, first=dict(mean=mean(first), min=min(first), max=max(first)),
                 revote=dict(mean=mean(revote), min=min(revote), max=max(revote)),
                 profile_update=pr, calldata=dict(bytes=cd[0]["bytes"], gas_mean=cdg,
                                                  floor_tokens=mean([c["floor_tokens"] for c in cd])),
                 intrinsic=21000)
        r["first_c5_store"] = r["first"]["mean"] - 21000 - cdg - pr["c1"] - pr["c2"] - pr["c3"] - pr["c4"]
        r["revote_c5_store"] = r["revote"]["mean"] - 21000 - cdg - pr["c1"] - pr["c2"] - pr["c3"] - pr["c4"]
        r["onchain_proof_share"] = (pr["c3"] + pr["c4"]) / r["first"]["mean"]
        out.append(r)
        print(f"nc={nc:2d} first {r['first']['mean']:>10,.0f}  revote {r['revote']['mean']:>10,.0f}  "
              f"C3 {pr['c3']:>8,.0f}  C4 {pr['c4']:>9,.0f}  calldata {cdg:>7,.0f}  deploy {pc.deploy_gas:,}")
    return out


def baseline(node, art, n_wallets=200):
    eid = keccak256(b"E3-baseline")
    bc = CH.BaselineContract(node, art["PerezCeesayElection"], eid)
    wallets = [BL.Wallet.new() for _ in range(n_wallets)]
    rc = bc.authorize([w.address for w in wallets[:100]])
    auth_batch = rc.gasUsed
    rc1 = bc.authorize([wallets[100].address])
    auth_single = rc1.gasUsed
    first, over = [], []
    for w in wallets[:VOTERS_PER_NC * 2]:
        cid = os.urandom(32)
        r_, s_, v_ = BL.sign(w, eid, 1, cid)
        first.append(bc.cast(w, cid, r_ + s_ + bytes([v_])).gasUsed)
        cid2 = os.urandom(32)
        r_, s_, v_ = BL.sign(w, eid, 2, cid2)
        over.append(bc.cast(w, cid2, r_ + s_ + bytes([v_])).gasUsed)
    res = dict(deploy_gas=bc.deploy_gas, authorize_batch100=auth_batch, authorize_per_wallet_batched=auth_batch / 100,
               authorize_single_tx=auth_single, cast_first=statistics.fmean(first), cast_overwrite=statistics.fmean(over))
    print("baseline:", {k: round(v) for k, v in res.items()})
    return res


def call_latency(node, art):
    """Indicative EVM execution time: eth_call(cast) minus eth_call(view)."""
    nc = 5
    eid = keccak256(b"E3-latency")
    t_cred = 2 ** 40
    tk, Y = HE.trustee_dkg(eid, 5, 3)
    keys, mvk = TIAC.keygen_dealer(5, 3)
    pc = CH.ProbaContract(node, art["ProbaElection"], eid, nc, Y, mvk, cfg(t_cred))
    w = BL.Wallet.new()
    tx, _ = BL.build_ballot(w, credential(eid, w, t_cred, keys, mvk), mvk, Y, eid, t_cred, 1, [1, 0, 0, 0, 0])
    n = reps(100)
    cast_t, view_t = [], []
    for i in range(n + 5):
        t0 = time.perf_counter(); ok, _ = pc.try_cast(w, tx); t1 = time.perf_counter()
        pc.c.functions.NC().call(); t2 = time.perf_counter()
        assert ok
        if i >= 5:
            cast_t.append((t1 - t0) * 1e3); view_t.append((t2 - t1) * 1e3)
    return dict(cast_call=summarize(cast_t), view_call=summarize(view_t),
                evm_estimate_ms=statistics.median(cast_t) - statistics.median(view_t)), dict(cast_call=cast_t, view_call=view_t)


# --------------------------------------------------------------------------
# Differential negative tests
# --------------------------------------------------------------------------
def _non_subgroup_point():
    p = 0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB
    x = 5
    while True:
        rhs = (pow(x, 3, p) + 4) % p
        y = pow(rhs, (p + 1) // 4, p)
        if y * y % p == rhs:
            b = b"\x00" * 16 + x.to_bytes(48, "big") + b"\x00" * 16 + y.to_bytes(48, "big")
            return b
        x += 1


def _resign(w, B, eid, seq):
    cid = BL.cid_digest(B)
    return BL.CastTx(B, cid, BL.sign(w, eid, seq, cid))


def negative_tests(node, art):
    nc = 5
    eid = keccak256(b"E3-negative")
    t_cred = 2 ** 40
    tk, Y = HE.trustee_dkg(eid, 5, 3)
    keys, mvk = TIAC.keygen_dealer(5, 3)
    pc = CH.ProbaContract(node, art["ProbaElection"], eid, nc, Y, mvk, cfg(t_cred))
    clock = {"now": node.w3.eth.get_block("latest").timestamp}
    board = BL.Board(eid, nc, Y, mvk, 0, 2 ** 40)
    alice, bob, eve = BL.Wallet.new(), BL.Wallet.new(), BL.Wallet.new()
    sa, sb = credential(eid, alice, t_cred, keys, mvk), credential(eid, bob, t_cred, keys, mvk)
    vote = [0, 0, 1, 0, 0]
    rows = []

    def tick(seconds):
        advance(node, seconds)
        clock["now"] = node.w3.eth.get_block("latest").timestamp

    def check(name, wallet, tx, expect, commit=False, contract=pc, brd=board, t=None):
        now = clock["now"]
        py_ok, py_reason = brd.accept(tx, t if t is not None else now) if not commit else (None, None)
        ch_ok, ch_reason = contract.try_cast(wallet, tx)
        if commit:
            rc = contract.cast(wallet, tx)
            clock["now"] = node.w3.eth.get_block(rc.blockNumber).timestamp
            py_ok, py_reason = brd.accept(tx, clock["now"])
            ch_ok = rc.status == 1
        agree = (py_ok == ch_ok) and (ch_ok or py_reason.split(":")[0] == ch_reason.split(":")[0]
                                      or ch_reason.startswith("precompile"))
        passed = (expect == "accept" and ch_ok) or (expect != "accept" and not ch_ok and ch_reason.startswith(expect))
        rows.append(dict(test=name, expected=expect, contract=ch_reason if not ch_ok else "accepted",
                         python=py_reason, agree=bool(agree), passed=bool(passed)))
        print(f"  {'PASS' if passed else 'FAIL'} {'=' if agree else '!'} {name:55s} contract={rows[-1]['contract']:14s} python={py_reason}")

    tx1, eb1 = BL.build_ballot(alice, sa, mvk, Y, eid, t_cred, 1, vote)
    check("valid first ballot", alice, tx1, "accept", commit=True)
    check("exact replay of an accepted transaction", alice, tx1, "C5")
    tx2, _ = BL.build_ballot(alice, sa, mvk, Y, eid, t_cred, 2, [1, 0, 0, 0, 0])
    check("re-vote before the minimum interval Delta_min", alice, tx2, "C5:interval")
    tick(DELTA_MIN)
    check("re-vote with larger sequence number after Delta_min", alice, tx2, "accept", commit=True)
    tick(DELTA_MIN)
    tx_big, _ = BL.build_ballot(alice, sa, mvk, Y, eid, t_cred, S_MAX + 1, [1, 0, 0, 0, 0])
    check("sequence number above S_max", alice, tx_big, "C5:seq")
    tx_old, _ = BL.build_ballot(alice, sa, mvk, Y, eid, t_cred, 1, [0, 1, 0, 0, 0])
    check("stale re-vote (seq not larger than Latest)", alice, tx_old, "C5")
    B = bytearray(tx1.B); B[300] ^= 1
    check("modified object bytes under the original cid/tau", alice, BL.CastTx(bytes(B), tx1.cid, tx1.tau), "C1:cid")
    txb, _ = BL.build_ballot(bob, sb, mvk, Y, eid, t_cred, 1, vote)
    forged = BL.CastTx(txb.B, txb.cid, BL.sign(eve, eid, 1, txb.cid))
    check("signature by a different wallet", bob, forged, "C2")
    fake_sigma = (mul1(g1, rand_scalar()), mul1(g1, rand_scalar()))
    txe, _ = BL.build_ballot(eve, fake_sigma, mvk, Y, eid, t_cred, 1, vote)
    check("uncredentialed wallet with a forged credential", eve, txe, "C3")
    txt, _ = BL.build_ballot(eve, sa, mvk, Y, eid, t_cred, 1, vote)
    check("credential transferred to another wallet", eve, txt, "C3")
    # ballot copying: Bob copies Alice's (ct, pi_bal) into his own object
    pa = BL.parse(tx1.B)
    A_v = BL.a_bytes(eid, bob.pk, t_cred, 1, nc, pa.ct_bytes, pa.pf.to_bytes())
    th = TIAC.prove(sb, mvk, eid, bob.pk, t_cred)
    check("ballot copying: victim's ciphertext+proof under own credential", bob, _resign(bob, A_v + th.to_bytes(), eid, 1), "C4")
    # proof bound to seq=1 but object claims seq=5
    A_v = BL.a_bytes(eid, alice.pk, t_cred, 5, nc, pa.ct_bytes, pa.pf.to_bytes())
    th = TIAC.prove(sa, mvk, eid, alice.pk, t_cred)
    check("proof replay to another sequence number", alice, _resign(alice, A_v + th.to_bytes(), eid, 5), "C4")

    def rogue(vote_):
        eb = HE.encrypt(Y, vote_)
        pf = HE.prove_ballot(eid, bob.pk, 3, Y, eb, [min(v, 1) for v in vote_])
        A_v = BL.a_bytes(eid, bob.pk, t_cred, 3, nc, eb.ct_bytes(), pf.to_bytes())
        th = TIAC.prove(sb, mvk, eid, bob.pk, t_cred)
        return _resign(bob, A_v + th.to_bytes(), eid, 3)
    check("over-vote (two selections)", bob, rogue([1, 1, 0, 0, 0]), "C4")
    check("non-binary slot (weight 2)", bob, rogue([2, 0, 0, 0, 0]), "C4")
    check("empty ballot (no selection)", bob, rogue([0, 0, 0, 0, 0]), "C4")
    # invalid group element (on curve, outside the prime-order subgroup)
    A_v = bytearray(BL.a_bytes(eid, bob.pk, t_cred, 4, nc, pa.ct_bytes, pa.pf.to_bytes()))
    A_v[192:320] = _non_subgroup_point()
    th = TIAC.prove(sb, mvk, eid, bob.pk, t_cred)
    check("ciphertext point outside the prime-order subgroup", bob, _resign(bob, bytes(A_v) + th.to_bytes(), eid, 4), "precompile")
    # cross-election replay
    eid2 = keccak256(b"E3-negative-2")
    pc2 = CH.ProbaContract(node, art["ProbaElection"], eid2, nc, Y, mvk, cfg(t_cred))
    check("cross-election replay (ballot of election 1 on election 2)", bob, txb, "C1:eid", contract=pc2,
          brd=BL.Board(eid2, nc, Y, mvk, 0, 2 ** 40))
    # expired credential / closed voting window
    now = clock["now"]
    pc3 = CH.ProbaContract(node, art["ProbaElection"], eid, nc, Y, mvk, cfg(now + 50))
    sx = credential(eid, bob, now + 50, keys, mvk)
    txx, _ = BL.build_ballot(bob, sx, mvk, Y, eid, now + 50, 1, vote)
    tick(3600)
    check("expired credential (block time > T_cred)", bob, txx, "C1:time", contract=pc3,
          brd=BL.Board(eid, nc, Y, mvk, 0, 2 ** 40))
    # wrong number of candidates
    txw, _ = BL.build_ballot(bob, sb, mvk, Y, eid, t_cred, 6, [1, 0, 0, 0])
    check("object for a different ballot shape (n_c = 4)", bob, txw, "C1")
    return rows


def main():
    node = CH.Node()
    try:
        art = CH.compile_contracts()
        env = environment(dict(anvil=tool_version([CH.ANVIL, "--version"]), solc=CH.solc_version(),
                               client=node.version(), hardfork="prague", solc_flags=" ".join(CH.SOLC_FLAGS),
                               runtime_bytes={k: v["runtime"] for k, v in art.items()}))
        print("E3a gas vs n_c")
        g = gas_vs_nc(node, art)
        print("E3b baseline")
        b = baseline(node, art)
        print("E3c eth_call latency")
        lat, lat_raw = call_latency(node, art)
        print(f"  cast eth_call median {lat['cast_call']['median']:.2f} ms, view {lat['view_call']['median']:.2f} ms")
        print("E3d differential negative tests")
        neg = negative_tests(node, art)
        dos = []
        for r in g:
            per_wallet = r["first"]["mean"] + (S_MAX - 1) * r["revote"]["mean"]
            dos.append(dict(nc=r["nc"], s_max=S_MAX, delta_min=DELTA_MIN, max_gas_per_wallet=per_wallet,
                            max_gas_rate_per_wallet_per_block=r["revote"]["mean"] * BLOCK_PERIOD_S / DELTA_MIN,
                            unlimited_revotes_per_30M_block=int(30_000_000 // r["revote"]["mean"])))
        thr = []
        for r in g:
            for G in GAS_LIMITS:
                per_block = int(G // r["first"]["mean"])
                thr.append(dict(nc=r["nc"], gas_limit=G, ballots_per_block=per_block,
                                ballots_per_s=per_block / BLOCK_PERIOD_S))
        save_raw("E3_eth_call", lat_raw)
        save_json("E3_contract", dict(env=env, gas=g, baseline=b, latency=lat, negative=neg,
                                      throughput_bound=thr, dos_bound=dos, block_period_s=BLOCK_PERIOD_S))
        assert all(r["passed"] and r["agree"] for r in neg), "negative test failure"
    finally:
        node.close()


if __name__ == "__main__":
    main()
