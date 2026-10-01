"""Builds LaTeX tables, PDF figures and a Markdown summary from results/*.json."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import matplotlib  # noqa: E402
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from bench.common import RESULTS  # noqa: E402

TAB = RESULTS / "tables"
FIG = RESULTS / "figures"
TAB.mkdir(parents=True, exist_ok=True)
FIG.mkdir(parents=True, exist_ok=True)
plt.rcParams.update({"font.size": 9, "font.family": "serif", "axes.grid": True, "grid.alpha": 0.3,
                     "figure.dpi": 150, "savefig.bbox": "tight"})


def load(name):
    p = RESULTS / f"{name}.json"
    return json.loads(p.read_text()) if p.exists() else None


def f(x, d=3):
    return f"{x:,.{d}f}"


def g(x):
    return f"{x:,.0f}".replace(",", "{,}")


def write(name, s):
    (TAB / name).write_text(s)


# ----------------------------------------------------------------------------- E1
def tab_primitives(e1):
    order = ["TIAC", "Registration", "ElGamal", "Chaum-Pedersen", "Wallet/encoding", "Composite", "Setup"]
    sym = lambda s: "T_{\\mathsf{" + s[2:].replace("_", "\\text{-}") + "}}"
    lines = [r"\begin{tabularx}{\textwidth}{l >{\raggedright\arraybackslash}X r r r r}", r"\toprule",
             r"\textbf{Notation} & \textbf{Operation} & \textbf{Mean} & \textbf{SD} & \textbf{Median} & \textbf{95\% CI} \\",
             r"\midrule"]
    first = True
    for grp in order:
        rows = [r for r in e1["results"] if r["group"] == grp]
        if not rows:
            continue
        if not first:
            lines.append(r"\midrule")
        first = False
        lines.append(r"\multicolumn{6}{l}{\emph{" + grp.replace("-", "--") + r"}} \\")
        for r in rows:
            lab = r["label"].replace("_", r"\_").replace("->", r"$\to$").replace("pi\\_iss", r"$\pi_{\mathsf{iss}}$")
            lab = lab.replace("tau\\_v", r"$\tau_v$").replace("m\\_v", "$m_v$").replace("d\\_v", "$d_v$")
            lab = lab.replace("n\\_c", "$n_c$").replace("t\\_i", "$t_i$").replace("t\\_d", "$t_d$").replace("n\\_i", "$n_i$").replace("n\\_d", "$n_d$")
            lab = lab.replace("H\\_attr", r"$H_{\mathsf{attr}}$").replace("H\\_cid", r"$H_{\mathsf{cid}}$").replace("B\\_v", "$B_v$").replace("T\\_cred", r"$T_{\mathsf{cred}}$")
            lab = lab.replace("10^4", "$10^4$").replace("H1", "$H_1$").replace("C1-C5", "C1--C5")
            lines.append(f"\\({sym(r['symbol'])}\\) & {lab} & {f(r['mean'])} & {f(r['sd'])} & {f(r['median'])} & "
                         f"[{f(r['ci95_lo'])}, {f(r['ci95_hi'])}] \\\\")
    lines += [r"\bottomrule", r"\end{tabularx}"]
    write("tab_primitives.tex", "\n".join(lines) + "\n")


# ----------------------------------------------------------------------------- E2
def fig_scaling(e2):
    fig, ax = plt.subplots(1, 3, figsize=(10.5, 2.8))
    nc = [r["nc"] for r in e2["nc"]]
    for key, lab, mk in (("voter", "Voter: ballot preparation", "o"), ("accept", "Verifier: Accept C1--C5", "s")):
        m = [r[key]["median"] for r in e2["nc"]]
        e = [r[key]["mean"] - r[key]["ci95_lo"] for r in e2["nc"]]
        ax[0].errorbar(nc, m, yerr=e, marker=mk, capsize=2, label=lab.replace("--", "–"))
    ax[0].set_xlabel("number of candidates $n_c$"); ax[0].set_ylabel("median CPU time per ballot (ms)")
    ax[0].set_title("(a) ballot cost vs. $n_c$"); ax[0].legend(fontsize=7)
    ti = [r["ti"] for r in e2["ti"]]
    ax[1].errorbar(ti, [r["total"]["median"] for r in e2["ti"]],
                   yerr=[r["total"]["mean"] - r["total"]["ci95_lo"] for r in e2["ti"]], marker="o", capsize=2,
                   label="all roles (sequential)")
    ax[1].errorbar(ti, [r["voter_cpu"]["median"] for r in e2["ti"]],
                   yerr=[r["voter_cpu"]["mean"] - r["voter_cpu"]["ci95_lo"] for r in e2["ti"]], marker="s",
                   capsize=2, label="voter only")
    ax[1].set_xlabel("issuance threshold $t_i$"); ax[1].set_ylabel("median CPU time per voter (ms)")
    ax[1].set_title("(b) registration vs. $t_i$"); ax[1].legend(fontsize=7)
    td = [r["td"] for r in e2["td"]]
    ax[2].errorbar(td, [r["trustee"]["mean"] for r in e2["td"]],
                   yerr=[r["trustee"]["mean"] - r["trustee"]["ci95_lo"] for r in e2["td"]], marker="o", capsize=2,
                   label="per trustee")
    ax[2].errorbar(td, [r["audit"]["mean"] for r in e2["td"]],
                   yerr=[r["audit"]["mean"] - r["audit"]["ci95_lo"] for r in e2["td"]], marker="s", capsize=2,
                   label="auditor: verify + combine")
    ax[2].set_xlabel("decryption threshold $t_d$"); ax[2].set_ylabel("CPU time ($n_c=5$) (ms)")
    ax[2].set_title("(c) tally vs. $t_d$"); ax[2].legend(fontsize=7)
    fig.tight_layout()
    fig.savefig(FIG / "fig_scaling.pdf"); fig.savefig(FIG / "fig_scaling.png")
    plt.close(fig)


def tab_nc(e2, e3):
    gas = {r["nc"]: r for r in e3["gas"]} if e3 else {}
    lines = [r"\begin{tabular}{r r r r r r r}", r"\toprule",
             r"\(n_c\) & \(|B_v|\) wire (B) & \(|B_v|\) compr.\ (B) & Voter (ms) & Accept, Python (ms) & First-vote gas & Re-vote gas \\",
             r"\midrule"]
    for r in e2["nc"]:
        gr = gas.get(r["nc"])
        lines.append(f"{r['nc']} & {g(r['wire_bytes'])} & {g(r['compressed_bytes'])} & {f(r['voter']['median'], 2)} "
                     f"& {f(r['accept']['median'], 2)} & {g(gr['first']['mean']) if gr else '--'} & "
                     f"{g(gr['revote']['mean']) if gr else '--'} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    write("tab_nc.tex", "\n".join(lines) + "\n")


def tab_ti(e2):
    lines = [r"\begin{tabular}{r r r r r r r}", r"\toprule",
             r"\((n_i,t_i)\) & PrepareIssue & \(t_i\times\)BlindIssue & \(t_i\times\)Unblind & Aggregate & Total & Voter only \\",
             r"\midrule"]
    for r in e2["ti"]:
        lines.append(f"({r['ni']},{r['ti']}) & {f(r['prep']['median'], 2)} & {f(r['issue_total']['median'], 2)} & "
                     f"{f(r['unblind_total']['median'], 2)} & {f(r['aggregate']['median'], 2)} & "
                     f"{f(r['total']['median'], 2)} & {f(r['voter_cpu']['median'], 2)} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    write("tab_ti.tex", "\n".join(lines) + "\n")


# ----------------------------------------------------------------------------- E3
def fig_gas(e3):
    rows = e3["gas"]
    nc = [r["nc"] for r in rows]
    parts = [
        ("intrinsic (21k)", [21000 for _ in rows]),
        ("calldata", [r["calldata"]["gas_mean"] for r in rows]),
        ("C1+C2 (CID, context, ecrecover)", [r["profile_update"]["c1"] + r["profile_update"]["c2"] for r in rows]),
        ("C3 credential (G2 mul + pairing)", [r["profile_update"]["c3"] for r in rows]),
        ("C4 ballot proofs (G1 MSM)", [r["profile_update"]["c4"] for r in rows]),
        ("C5 + Latest[pk] store + event", [r["first_c5_store"] for r in rows]),
    ]
    fig, ax = plt.subplots(figsize=(6.4, 3.0))
    bottom = [0] * len(rows)
    xs = list(range(len(rows)))
    for lab, vals in parts:
        ax.bar(xs, [v / 1e3 for v in vals], bottom=[b / 1e3 for b in bottom], label=lab, width=0.65)
        bottom = [b + v for b, v in zip(bottom, vals)]
    b = e3["baseline"]
    base = b["cast_first"] + b["authorize_per_wallet_batched"]
    ax.axhline(base / 1e3, color="k", ls="--", lw=1, label="Perez–Ceesay baseline: authorize + cast")
    ax.set_xticks(xs, [str(n) for n in nc]); ax.set_xlabel("number of candidates $n_c$")
    ax.set_ylabel("gas per first ballot (×10³)"); ax.legend(fontsize=6.5, loc="upper left")
    fig.tight_layout(); fig.savefig(FIG / "fig_gas.pdf"); fig.savefig(FIG / "fig_gas.png"); plt.close(fig)


def tab_gas(e3):
    lines = [r"\begin{tabular}{r r r r r r r r}", r"\toprule",
             r"\(n_c\) & Calldata & C1+C2 & C3 & C4 & C5+store & First vote & Re-vote \\", r"\midrule"]
    for r in e3["gas"]:
        p = r["profile_update"]
        lines.append(f"{r['nc']} & {g(r['calldata']['gas_mean'])} & {g(p['c1'] + p['c2'])} & {g(p['c3'])} & "
                     f"{g(p['c4'])} & {g(r['first_c5_store'])} & {g(r['first']['mean'])} & {g(r['revote']['mean'])} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    write("tab_gas.tex", "\n".join(lines) + "\n")


def tab_negative(e3):
    lines = [r"\begin{tabularx}{\textwidth}{>{\raggedright\arraybackslash}X l l c}", r"\toprule",
             r"\textbf{Submitted transaction} & \textbf{Contract} & \textbf{Python \(\Accept\)} & \textbf{Agree} \\",
             r"\midrule"]
    for r in e3["negative"]:
        py = r["python"].split(":")
        py = ":".join(py[:2]) if not py[0].startswith("accept") else "accepted"
        name = r["test"]
        for a, b in (("Latest", r"\(\Latest\)"), ("cid/tau", r"\(\cid_v/\tau_v\)"), ("T_cred", r"\(T_{\mathsf{cred}}\)"),
                     ("n_c = 4", r"\(n_c=4\)"), ("> ", r"\(>\) "), ("seq ", r"\(\seq_v\) "), ("+", " and ")):
            name = name.replace(a, b)
        name = name.replace("Delta_min", r"\(\Delta_{\min}\)").replace("S_max", r"\(S_{\max}\)")
        lines.append(f"{name[0].upper() + name[1:]} & \\texttt{{{r['contract']}}} & \\texttt{{{py}}} & "
                     f"{'yes' if r['agree'] else 'no'} \\\\")
    lines += [r"\bottomrule", r"\end{tabularx}"]
    write("tab_negative.tex", "\n".join(lines) + "\n")


# ----------------------------------------------------------------------------- E4
def fig_e2e(e4):
    runs = e4["runs"]
    nv = [r["nv"] for r in runs]
    fig, ax = plt.subplots(1, 2, figsize=(8.4, 2.8))
    for key, lab, mk in (("registration", "registration (Alg. 6)", "o"), ("casting", "casting incl. re-votes (Alg. 7)", "s"),
                         ("audit_total", "audit + tally (Alg. 8)", "^")):
        ax[0].plot(nv, [r["phase_seconds"][key] for r in runs], marker=mk, label=lab)
    ax[0].set_xlabel("number of voters $n_v$"); ax[0].set_ylabel("wall-clock time (s)")
    ax[0].set_title("(a) phase duration"); ax[0].legend(fontsize=7)
    comp = [("ballot", "ballot preparation"), ("ipfs_add", "IPFS add+pin"), ("ipfs_cat", "IPFS retrieve+check"),
            ("submit", "tx submission + receipt")]
    xs = list(range(len(runs)))
    bottom = [0] * len(runs)
    for key, lab in comp:
        vals = [r["per_voter"][key]["mean"] for r in runs]
        ax[1].bar(xs, vals, bottom=bottom, label=lab, width=0.6)
        bottom = [b + v for b, v in zip(bottom, vals)]
    ax[1].set_xticks(xs, [str(n) for n in nv]); ax[1].set_xlabel("number of voters $n_v$")
    ax[1].set_ylabel("mean time per cast (ms)"); ax[1].set_title("(b) casting latency components")
    ax[1].set_ylim(0, max(bottom) * 1.45); ax[1].legend(fontsize=6.5, loc="upper left", ncol=2)
    fig.tight_layout(); fig.savefig(FIG / "fig_e2e.pdf"); fig.savefig(FIG / "fig_e2e.png"); plt.close(fig)


def tab_e2e(e4):
    lines = [r"\begin{tabular}{r r r r r r r r}", r"\toprule",
             r"\(n_v\) & Tx & Setup (s) & Registration (s) & Casting (s) & Audit+tally (s) & Gas/tx & Tally correct \\",
             r"\midrule"]
    for r in e4["runs"]:
        p = r["phase_seconds"]
        lines.append(f"{g(r['nv'])} & {g(r['transactions'])} & {f(p['setup'], 2)} & {f(p['registration'], 2)} & "
                     f"{f(p['casting'], 2)} & {f(p['audit_total'], 2)} & {g(r['gas_per_tx'])} & "
                     f"{'yes' if r['tally_correct'] else 'no'} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    write("tab_e2e.tex", "\n".join(lines) + "\n")


def summary(e1, e2, e3, e4):
    out = ["# PROBA v3.4 benchmark summary", ""]
    if e1:
        env = e1["env"]
        out += [f"Machine: {env['cpu']}, {env['logical_cpus']} vCPU, {env['memory']}, {env['distro']}, Python {env['python']}", ""]
        out += ["## E1 primitives (ms)", "", "| symbol | mean | sd | median | n | operation |", "|---|---|---|---|---|---|"]
        for r in e1["results"]:
            out.append(f"| {r['symbol']} | {r['mean']:.4f} | {r['sd']:.4f} | {r['median']:.4f} | {r['n']} | {r['label']} |")
    if e3:
        out += ["", "## E3 gas", "", "| nc | first | revote | C3 | C4 | calldata |", "|---|---|---|---|---|---|"]
        for r in e3["gas"]:
            out.append(f"| {r['nc']} | {r['first']['mean']:.0f} | {r['revote']['mean']:.0f} | {r['profile_update']['c3']:.0f} "
                       f"| {r['profile_update']['c4']:.0f} | {r['calldata']['gas_mean']:.0f} |")
        out += ["", f"Baseline: {json.dumps({k: round(v) for k, v in e3['baseline'].items()})}",
                f"Negative tests: {sum(r['passed'] for r in e3['negative'])}/{len(e3['negative'])} passed, "
                f"{sum(r['agree'] for r in e3['negative'])} agree"]
    if e4:
        out += ["", "## E4 end-to-end", ""]
        for r in e4["runs"]:
            out.append(f"- nv={r['nv']}: {json.dumps({k: round(v, 2) for k, v in r['phase_seconds'].items()})}, "
                       f"tally={r['tally']}, gas/tx={r['gas_per_tx']:.0f}")
    (RESULTS / "SUMMARY.md").write_text("\n".join(out) + "\n")


def main():
    e1, e2, e3, e4 = (load(n) for n in ("E1_primitives", "E2_scaling", "E3_contract", "E4_e2e"))
    if e1:
        tab_primitives(e1)
    if e2:
        fig_scaling(e2); tab_nc(e2, e3); tab_ti(e2)
    if e3:
        fig_gas(e3); tab_gas(e3); tab_negative(e3)
    if e4:
        fig_e2e(e4); tab_e2e(e4)
    summary(e1, e2, e3, e4)
    print("tables :", sorted(p.name for p in TAB.iterdir()))
    print("figures:", sorted(p.name for p in FIG.iterdir()))


if __name__ == "__main__":
    main()
