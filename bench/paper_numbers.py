"""Generates results/paper/: proba_numbers.tex (every number quoted in Section 7
and in the abstract/conclusion), tables/ and figures/.

    python bench/paper_numbers.py                      # from $PROBA_RESULTS (default results/)
    PROBA_COMPARE=results_linux_x86_vm python bench/paper_numbers.py   # + cross-platform macros

In the manuscript:  \\input{proba_numbers.tex}  and  \\PN{key}.
"""
from __future__ import annotations

import json
import os
import shutil
import statistics
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from bench.common import RESULTS  # noqa: E402

OUT = RESULTS / "paper"


def load(d: Path, n):
    p = d / f"{n}.json"
    return json.loads(p.read_text()) if p.exists() else None


def ms(x):
    return f"{x:.3f}" if x < 0.1 else f"{x:.2f}"


def gas(x):
    return f"{x:,.0f}".replace(",", "{,}")


def kgas(x):
    return f"{x / 1000:.1f}"


def tex_escape(s):
    return s.replace("_", r"\_").replace("%", r"\%").replace("&", r"\&")


def main():
    e1, e2, e3, e4 = (load(RESULTS, n) for n in ("E1_primitives", "E2_scaling", "E3_contract", "E4_e2e"))
    assert e1 and e2 and e3 and e4, "run E1-E4 first"
    N = {}
    env = e1["env"]
    # ---------------------------------------------------------------- environment
    N["EnvCPU"] = tex_escape(env["cpu"])
    N["EnvMemory"] = env["memory"]
    N["EnvOS"] = tex_escape(env.get("distro") or env["os"])
    N["EnvPython"] = env["python"]
    N["EnvBackend"] = tex_escape(env.get("wallet_backend", "coincurve"))
    N["EnvArkworks"] = env["py_arkworks_bls12381"]
    N["EnvCoincurve"] = env.get("coincurve", "n/a")
    e3env = e3["env"]
    N["EnvAnvil"] = e3env["anvil"].split("Version:")[-1].strip().split("-")[0]
    N["EnvSolc"] = e3env["solc"].split("Version:")[-1].strip().split("+")[0]
    N["EnvKubo"] = e4["env"].get("ipfs", "kubo").split()[1] if "ipfs" in e4["env"] else "n/a"
    N["RuntimeBytes"] = gas(e3env["runtime_bytes"]["ProbaElection"])
    # ---------------------------------------------------------------- E1
    R = {r["symbol"]: r for r in e1["results"]}
    for k, r in R.items():
        N[k] = ms(r["mean"])
        N[k + ":median"] = ms(r["median"])
    m = lambda k: R[k]["mean"]
    nc = e1["params"]["nc"]
    N["CredSum"] = ms(m("T_PrCred") + m("T_VrCred"))
    N["VoterComp"] = ms(nc * (m("T_Enc") + m("T_PrVV")) + m("T_PrVS") + m("T_PrCred"))
    N["AcceptComp"] = ms(m("T_Parse") + nc * m("T_VrVV") + m("T_VrVS") + m("T_VrCred") + m("T_SigVr"))
    N["IssuerPerShare"] = ms(m("T_IssChk") + m("T_Issue"))
    cv = sorted(((r["sd"] / r["mean"] * 100, k) for k, r in R.items() if r["mean"] >= 0.1), reverse=True)
    N["CVMaxOp"] = "T_{\\mathsf{" + cv[0][1][2:].replace("_", "\\text{-}") + "}}"
    N["CVMax"] = f"{cv[0][0]:.0f}"
    N["CVMaxOpMedian"] = ms(R[cv[0][1]]["median"])
    N["CVSecond"] = f"{cv[1][0]:.1f}"
    N["CVMedian"] = f"{statistics.median(c for c, _ in cv):.1f}"
    # ---------------------------------------------------------------- E2
    ncs = e2["nc"]
    N["NcSlopeVoter"] = f"{(ncs[-1]['voter']['median'] - ncs[0]['voter']['median']) / (ncs[-1]['nc'] - ncs[0]['nc']):.2f}"
    N["NcSlopeAccept"] = f"{(ncs[-1]['accept']['median'] - ncs[0]['accept']['median']) / (ncs[-1]['nc'] - ncs[0]['nc']):.2f}"
    five = [r for r in ncs if r["nc"] == 5][0]
    N["WireBytes"] = gas(five["wire_bytes"])
    N["ComprBytes"] = gas(five["compressed_bytes"])
    tis = e2["ti"]
    dti = tis[-1]["ti"] - tis[0]["ti"]
    N["TiSlopeTotal"] = f"{(tis[-1]['total']['median'] - tis[0]['total']['median']) / dti:.1f}"
    N["TiSlopeVoter"] = f"{(tis[-1]['voter_cpu']['median'] - tis[0]['voter_cpu']['median']) / dti:.1f}"
    N["TiSlopeIssuer"] = f"{(tis[-1]['issue_total']['median'] - tis[0]['issue_total']['median']) / dti:.1f}"
    t3 = [r for r in tis if r["ti"] == 3][0]
    N["RegVoter"] = ms(t3["voter_cpu"]["median"])
    N["RegTotal"] = ms(t3["total"]["median"])
    td3 = [r for r in e2["td"] if r["td"] == 3][0]
    N["TallyTrustee"] = ms(td3["trustee"]["mean"])
    N["TallyAudit"] = ms(td3["audit"]["mean"])
    # ---------------------------------------------------------------- E3
    G = e3["gas"]
    g5 = [r for r in G if r["nc"] == 5][0]
    p5 = g5["profile_update"]
    slope = (G[-1]["first"]["mean"] - G[0]["first"]["mean"]) / (G[-1]["nc"] - G[0]["nc"])
    N["GasSlope"] = gas(round(slope, -2))
    N["GasIntercept"] = gas(round(G[0]["first"]["mean"] - G[0]["nc"] * slope, -2))
    N["GasFirst"] = gas(g5["first"]["mean"])
    N["GasRevote"] = gas(g5["revote"]["mean"])
    N["GasFirstM"] = f"{g5['first']['mean'] / 1e6:.2f}"
    N["GasFirstK"] = f"{g5['first']['mean'] / 1e3:.0f}"
    N["GasCthreeMin"] = kgas(min(r["profile_update"]["c3"] for r in G))
    N["GasCthreeMax"] = kgas(max(r["profile_update"]["c3"] for r in G))
    N["GasCthree"] = kgas(p5["c3"])
    N["GasCfourSlope"] = f"{(G[-1]['profile_update']['c4'] - G[0]['profile_update']['c4']) / (G[-1]['nc'] - G[0]['nc']) / 1000:.0f}"
    N["GasProofShare"] = f"{g5['onchain_proof_share'] * 100:.1f}"
    N["GasConetwo"] = kgas(p5["c1"] + p5["c2"])
    N["GasStoreFirst"] = kgas(g5["first_c5_store"])
    N["GasRevoteSaving"] = kgas(g5["first"]["mean"] - g5["revote"]["mean"])
    N["GasNoProofs"] = f"{(g5['first']['mean'] - p5['c3'] - p5['c4']) / 1e3:.0f}"
    N["CalldataBytes"] = gas(g5["calldata"]["bytes"])
    N["DeployGasM"] = f"{g5['deploy_gas'] / 1e6:.2f}"
    b = e3["baseline"]
    N["BaseAuthBatched"] = gas(b["authorize_per_wallet_batched"])
    N["BaseAuthSingle"] = gas(b["authorize_single_tx"])
    N["BaseCast"] = gas(b["cast_first"])
    N["BaseOverwrite"] = gas(b["cast_overwrite"])
    per_voter = b["cast_first"] + b["authorize_per_wallet_batched"]
    N["BasePerVoterK"] = f"{per_voter / 1e3:.1f}"
    N["BaseRatio"] = f"{g5['first']['mean'] / per_voter:.0f}"
    N["BaseDeployM"] = f"{b['deploy_gas'] / 1e6:.2f}"
    thr = {t["gas_limit"]: t for t in e3["throughput_bound"] if t["nc"] == 5}
    for G_, name in ((30_000_000, "Thirty"), (60_000_000, "Sixty"), (100_000_000, "Hundred")):
        N[f"Blk{name}"] = str(thr[G_]["ballots_per_block"])
        N[f"Rate{name}"] = f"{thr[G_]['ballots_per_s']:g}"
    blocks10k = -(-10_000 // thr[30_000_000]["ballots_per_block"])
    N["TenKBlocks"] = str(blocks10k)
    N["TenKMinutes"] = f"{blocks10k * e3['block_period_s'] / 60:.0f}"
    N["BlockPeriod"] = str(e3["block_period_s"])
    d5 = [d for d in e3["dos_bound"] if d["nc"] == 5][0]
    N["SMax"] = str(d5["s_max"])
    N["DeltaMin"] = str(d5["delta_min"])
    N["DosUnlimited"] = str(d5["unlimited_revotes_per_30M_block"])
    N["DosWalletsToFill"] = gas(thr[30_000_000]["ballots_per_block"] * d5["delta_min"] / e3["block_period_s"])
    N["DosPerWalletM"] = f"{d5['max_gas_per_wallet'] / 1e6:.1f}"
    N["EvmMs"] = f"{e3['latency']['evm_estimate_ms']:.1f}"
    neg = e3["negative"]
    N["NegTotal"] = str(len(neg))
    N["NegPassed"] = str(sum(r["passed"] for r in neg))
    N["NegAgree"] = str(sum(r["agree"] for r in neg))
    # ---------------------------------------------------------------- E4
    runs = e4["runs"]
    rng = lambda key: (min(r["per_voter"][key]["mean"] for r in runs), max(r["per_voter"][key]["mean"] for r in runs))
    for key, name in (("register", "Reg"), ("ballot", "Ballot"), ("ipfs_add", "IpfsAdd"), ("ipfs_cat", "IpfsCat"),
                      ("submit", "Submit")):
        lo, hi = rng(key)
        N[f"E4{name}Lo"], N[f"E4{name}Hi"] = ms(lo), ms(hi)
    cast = [sum(r["per_voter"][k]["mean"] for k in ("ballot", "ipfs_add", "ipfs_cat", "submit")) for r in runs]
    N["E4CastLo"], N["E4CastHi"] = f"{min(cast):.0f}", f"{max(cast):.0f}"
    last = runs[-1]
    comp = {"ballot preparation": last["per_voter"]["ballot"]["mean"],
            "adding and pinning the object in the local IPFS node": last["per_voter"]["ipfs_add"]["mean"],
            "transaction submission with receipt": last["per_voter"]["submit"]["mean"]}
    N["E4Largest"] = max(comp, key=comp.get)
    N["E4LargestIsCrypto"] = "1" if N["E4Largest"] == "ballot preparation" else "0"
    N["E4NvMax"] = gas(last["nv"])
    N["E4TxMax"] = gas(last["transactions"])
    N["E4AuditTotal"] = f"{last['phase_seconds']['audit_total']:.1f}"
    N["E4TallyOnly"] = f"{last['phase_seconds']['trustees'] + last['phase_seconds']['combine']:.2f}"
    N["E4LedgerFetch"] = ms(statistics.fmean(r["audit_ledger_fetch"]["mean"] for r in runs))
    N["E4IpfsFetch"] = ms(statistics.fmean(r["audit_fetch"]["mean"] for r in runs))
    N["E4AllCorrect"] = "1" if all(r["tally_correct"] for r in runs) else "0"
    # ---------------------------------------------------------------- cross-platform comparison
    cmp_dir = os.environ.get("PROBA_COMPARE")
    N["Xplat"] = "0"
    if cmp_dir:
        c1, c3 = load(Path(cmp_dir), "E1_primitives"), load(Path(cmp_dir), "E3_contract")
        if c1 and c3:
            diffs = []
            for a, bb in zip(e3["gas"], c3["gas"]):
                diffs += [abs(a[k]["mean"] - bb[k]["mean"]) for k in ("first", "revote")]
                diffs += [abs(a["profile_update"][c] - bb["profile_update"][c]) for c in ("c1", "c2", "c3", "c4", "c5")]
            diffs += [abs(e3["baseline"][k] - c3["baseline"][k]) for k in e3["baseline"]]
            C = {r["symbol"]: r["mean"] for r in c1["results"]}
            rat = [C[k] / R[k]["mean"] for k in R if R[k]["mean"] >= 0.1 and k in C]
            N["Xplat"] = "1"
            N["XplatCPU"] = tex_escape(c1["env"]["cpu"])
            N["XplatOS"] = tex_escape(c1["env"].get("distro") or c1["env"]["os"])
            N["XplatCores"] = str(c1["env"]["logical_cpus"])
            N["XplatGasDiff"] = f"{max(diffs):.0f}"
            N["XplatRatioMin"] = f"{min(rat):.1f}"
            N["XplatRatioMax"] = f"{max(rat):.1f}"
            N["XplatRatioMedian"] = f"{statistics.median(rat):.1f}"
            N["XplatVerdicts"] = "1" if [r["contract"] for r in neg] == [r["contract"] for r in c3["negative"]] else "0"
    # ---------------------------------------------------------------- write
    OUT.mkdir(parents=True, exist_ok=True)
    lines = ["% Generated by bench/paper_numbers.py from " + str(RESULTS.resolve().name) + " -- do not edit.",
             f"% machine: {env['cpu']} | {env.get('distro')} | Python {env['python']} | {env.get('wallet_backend')}",
             r"\providecommand{\pndef}[2]{\expandafter\def\csname pn@#1\endcsname{#2}}",
             r"\providecommand{\PN}[1]{\ifcsname pn@#1\endcsname\csname pn@#1\endcsname\else\textbf{??#1??}\fi}",
             r"\providecommand{\PNif}[3]{\if1\PN{#1}#2\else#3\fi}"]
    for k in sorted(N):
        lines.append(f"\\pndef{{{k}}}{{{N[k]}}}")
    (OUT / "proba_numbers.tex").write_text("\n".join(lines) + "\n")
    for sub in ("tables", "figures"):
        if (OUT / sub).exists():
            shutil.rmtree(OUT / sub)
        shutil.copytree(RESULTS / sub, OUT / sub)
    print(f"wrote {OUT / 'proba_numbers.tex'} ({len(N)} values), tables/, figures/")


if __name__ == "__main__":
    main()
