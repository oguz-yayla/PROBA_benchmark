# PROBA v3.4 — benchmark and experiment suite

Reference implementation, smart contracts and experiments for Section 7 of
*[PROBA: Threshold-Authorized and Privacy-Preserving Blockchain-Powered Helios](https://github.com/oguz-yayla/PROBA_benchmark/blob/main/PROBA-%20Threshold-Authorized%20and%20Privacy-Preserving%20Blockchain-Powered%20Helios.pdf)*.
Everything follows the normative Algorithms 5–8 and the BLS12-381 instantiation
of Section 3.3 of the v3.4 manuscript.


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
