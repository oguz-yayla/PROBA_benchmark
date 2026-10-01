#!/usr/bin/env bash
# Runs the tests and experiments E1-E4, then builds tables and figures.
#   PROBA_QUICK=1 ./run_all.sh     -> reduced repetitions (smoke test, ~5 min)
set -euo pipefail
cd "$(dirname "$0")"
if [ -f .venv/bin/activate ]; then
  # shellcheck disable=SC1091
  . .venv/bin/activate
fi
export PATH="$HOME/.proba-tools/bin:/opt/foundry:$PATH"
export PYTHONPATH="$PWD"
mkdir -p results
python bench/check_env.py || { echo "run ./setup.sh first"; exit 1; }
python -m pytest -q tests/                              | tee results/tests.log
python bench/bench_primitives.py                        | tee results/E1.log
python bench/bench_scaling.py                           | tee results/E2.log
python bench/bench_contract.py 2>results/E3.stderr.log  | tee results/E3.log
python bench/bench_e2e.py      2>results/E4.stderr.log  | tee results/E4.log
python bench/report.py                                  | tee results/report.log
# cross-platform sentence of Section 7.1, if an independent run is present
if [ -d results_linux_x86_vm ]; then export PROBA_COMPARE="$PWD/results_linux_x86_vm"; fi
python bench/paper_numbers.py                           | tee -a results/report.log
echo
echo "Manuscript inputs written to results/paper/ (proba_numbers.tex, tables/, figures/)."
