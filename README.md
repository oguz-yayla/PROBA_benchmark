# PROBA v3.4 — benchmark and experiment suite

Reference implementation, smart contracts and experiments for Section 7 of
*PROBA: Threshold-Authorized and Privacy-Preserving Blockchain-Powered Helios*.
Everything follows the normative Algorithms 5–8 and the BLS12-381 instantiation
of Section 3.3 of the v3.4 manuscript.

## Changes with respect to v3.2

| Change | Where | Effect on measurements |
|---|---|---|
| Credential showing is the re-randomised credential `(h', s')`; `kappa`, `nu`, `pi_show` and `d_v` removed (they hid nothing and did not bind the ballot) | `tiac.py`, `ballot.py`, contract C3 | `|B_v|` = 512 + 384 n_c; C3 ≈ 134k gas instead of ≈ 221k |
| C5 rate limit: `seq <= S_max`, re-vote at least `Delta_min` after the previous accepted ballot (`t_last` packed in the same slot) | `ballot.py`, contract C5 | negligible gas; two new negative tests |
| Every issuer authenticates the identity itself (challenge-response), keeps a one-share-per-identity record and reports shares; a pending registration can be released only if no share was returned | `registration.py` | registration time includes `T_IdResp` / `T_IssChk` |
| Auditor recovers every effective object from transaction calldata and from IPFS and checks they are identical; checks `|S| <= #receipts` | `bench_e2e.py` | new audit timing |
| `h1`, `g_E` documented as hash-to-curve (tested), including a test that shows the forgery if `log(h1)` were known | `crypto.py`, tests | – |
| Every number in Section 7 is generated (`bench/paper_numbers.py`) | `results/paper/` | – |

## Layout

```
proba/                 reference implementation
  crypto.py            BLS12-381 helpers, EIP-2537 encoding, domain-separated hashes
  tiac.py              threshold-issued anonymous credential (Sec. 3.3.1): DKG, PrepareIssue,
                       BlindIssue, Unblind, Aggregate, Prove, Verify
  elgamal.py           threshold exponential ElGamal in G_E = G1, Chaum–Pedersen proofs,
                       trustee DKG, partial decryption, BSGS tally recovery
  ballot.py            wallet (secp256k1/EIP-191), ballot object B_v, CIDv1, Accept (C1–C5)
  registration.py      RegDB state machine, one-use tokens, issuers (Algorithm 6)
  chain.py             anvil (Prague) lifecycle, solc compilation, deployment, casting
  ipfs.py              local kubo node (offline) used as pinning service
contracts/
  ProbaElection.sol          Algorithm 7, checks C1–C5 on EIP-2537 precompiles
  PerezCeesayElection.sol    baseline of Algorithm 4
bench/
  bench_primitives.py  E1  primitive microbenchmarks (Table 5)
  bench_scaling.py     E2  scaling in n_c, t_i, t_d (Fig. 3, Tables 7–8)
  bench_contract.py    E3  gas, C1–C5 breakdown, baseline, differential negative tests (Tables 9–10, Fig. 4)
  bench_e2e.py         E4  complete elections, n_v = 100…1000 (Table 11, Fig. 5)
  report.py            LaTeX tables, PDF figures, SUMMARY.md
  paper_numbers.py     results/paper/: proba_numbers.tex (+ tables/, figures/) for the manuscript
  check_env.py         preflight check of packages and tools
tests/test_protocol.py correctness and soundness sanity tests (pytest, 15 tests)
results_linux_x86_vm/  v3.4 run on a single-vCPU Intel Xeon VM (cross-platform reference)
archive/results_v3.2_M4/  superseded v3.2 run (M4), kept for the response letter
```

## Running

```bash
./setup.sh                    # creates .venv, installs Python deps, anvil, solc 0.8.28, kubo 0.38.1
./run_all.sh                  # preflight check, tests, E1–E4, report  (~15 min on one vCPU)
PROBA_QUICK=1 ./run_all.sh    # smoke test with reduced repetitions (~5 min)
```

`setup.sh` detects macOS (Apple Silicon / Intel) and Linux (x86-64 / arm64), downloads the
matching binaries into `~/.proba-tools/bin`, and installs the Python packages into `./.venv`
(Homebrew's Python rejects system-wide `pip install`, PEP 668). `run_all.sh` activates the venv
itself. To run a single experiment manually:

```bash
source .venv/bin/activate
export PATH="$HOME/.proba-tools/bin:$PATH" PYTHONPATH="$PWD"
python bench/check_env.py          # tells you exactly what is missing, if anything
python bench/bench_contract.py
```

`PROBA_RESULTS=/some/dir` redirects the output directory.

### macOS and Python 3.14

`coincurve` 21.0.0 (libsecp256k1 bindings) publishes wheels only up to CPython 3.13, and its
source build fails on 3.14. `setup.sh` therefore prefers `python3.13` when present. On 3.14 the
suite still runs: wallet signatures then use `proba/secp256k1_fallback.py` (OpenSSL signing plus a
pure-Python `ecrecover`), which is bit-exact with the contract (tested) but slower
(T_Sign ≈ 4 ms, T_SigVr ≈ 2.5 ms instead of ≈ 0.04–0.05 ms). The active backend is recorded as
`wallet_backend` in every `results/*.json`. **For numbers comparable with the paper, use 3.13:**

```bash
brew install python@3.13
rm -rf .venv && PYTHON=python3.13 ./setup.sh
```

Gas values are deterministic and independent of the machine and of the wallet backend.

## Design notes

* **One encoding everywhere.** B_v is serialized in the EIP-2537 wire format, so the same bytes are
  hashed into the CID, pinned in IPFS, sent as calldata and consumed by the precompiles.
  `H_cid` = CIDv1(raw, sha2-256); identical to `ipfs add --cid-version=1 --raw-leaves`.
* **Same Fiat–Shamir function on- and off-chain.** `keccak256`, 512-bit wide reduction mod r.
* **Voters submit from their own zero-balance wallets** (zero base fee and gas price), i.e. the
  subsidised-fee policy of Definition 3.4.
* Gas per check is measured in-contract with `gasleft()` (`castProfiled`); headline gas comes from
  the un-instrumented `cast`.

## What is *not* measured

anvil is a single-node development chain with instant sealing: EVM execution and gas are exact
(Prague rules), but IBFT consensus, validator networking and finality latency are not modelled.
IPFS runs offline on localhost (no WAN transfer or multi-provider replication). Civil-identity
authentication, the anonymous channel of Assumption 3.1 and browser clients are out of scope.
All roles run sequentially on one core. The code is a research prototype and has not been audited.

## From the M4 run to the manuscript

```bash
./run_all.sh                       # writes results/ and results/paper/
cp -r results/paper/* <manuscript-folder>/   # proba_numbers.tex, tables/, figures/
pdflatex main_v3_4 && bibtex main_v3_4 && pdflatex main_v3_4 && pdflatex main_v3_4
```

`main_v3_4.tex` contains `\input{proba_numbers.tex}` and quotes every measured value as
`\PN{key}`; tables are `\input` from `tables/`. A missing key prints `??key??` in bold.
When `results_linux_x86_vm/` is present, `run_all.sh` also generates the cross-platform sentence
of Section 7.1 (`PROBA_COMPARE`).

## Environment of the runs

`results_linux_x86_vm/`: Intel Xeon @ 2.80 GHz (1 vCPU), Ubuntu 24.04, Python 3.12.3,
coincurve 21.0.0, py_arkworks_bls12381 0.5.0, web3 8.0.0, anvil 1.5.1 (Prague), solc 0.8.28
(`--via-ir --optimize-runs 200`), kubo 0.38.1. The manuscript numbers are to be produced on the
Apple M4 (`results/`, created by `./run_all.sh`). Full metadata is stored in every `*.json` under `env`.
