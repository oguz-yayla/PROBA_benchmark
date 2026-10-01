"""Preflight check: verifies Python packages and external tools before a run.

    python3 bench/check_env.py      # exit status 0 = ready, 1 = something is missing
"""
from __future__ import annotations

import importlib
import os
import shutil
import subprocess
import sys

PKGS = [  # (import name, pip name, required)
    ("py_arkworks_bls12381", "py_arkworks_bls12381", True),
    ("Crypto.Hash.keccak", "pycryptodome", True),
    ("cryptography", "cryptography", True),
    ("web3", "web3", True),
    ("eth_account", "web3", True),
    ("requests", "requests", True),
    ("scipy", "scipy", True),
    ("matplotlib", "matplotlib", True),
    ("pytest", "pytest", True),
    ("coincurve", "coincurve", False),
]
TOOLS = [("anvil", "Foundry anvil (Prague / EIP-2537)"), ("solc", "solc 0.8.28"), ("ipfs", "kubo 0.38.1")]
EXTRA_PATHS = [os.path.expanduser("~/.proba-tools/bin"), "/opt/foundry", "/opt"]


def which(name):
    p = shutil.which(name)
    if p:
        return p
    for d in EXTRA_PATHS:
        c = os.path.join(d, name)
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def main():
    ok = True
    print(f"Python {sys.version.split()[0]} at {sys.executable}")
    in_venv = sys.prefix != getattr(sys, "base_prefix", sys.prefix)
    if not in_venv:
        print("  note: not running inside a virtual environment (./setup.sh creates .venv)")
    for mod, pipname, required in PKGS:
        try:
            importlib.import_module(mod)
            print(f"  [ok]   {mod}")
        except Exception as e:
            if required:
                ok = False
                print(f"  [MISS] {mod:22s} -> pip install {pipname}   ({type(e).__name__}: {e})")
            else:
                print(f"  [opt]  {mod:22s} not available -> wallet signatures use the slower "
                      f"cryptography fallback (see README, 'Python 3.14')")
    for name, desc in TOOLS:
        p = which(name)
        if not p:
            ok = False
            print(f"  [MISS] {name:22s} {desc} not found on PATH (run ./setup.sh and export PATH)")
            continue
        try:
            out = subprocess.run([p, "--version"], capture_output=True, text=True, timeout=30)
            v = (out.stdout or out.stderr).strip().splitlines()
            print(f"  [ok]   {name:22s} {p}  {v[-1] if name == 'solc' else v[0]}")
        except OSError as e:   # e.g. "Exec format error" for a binary of the wrong platform
            ok = False
            print(f"  [BAD]  {name:22s} {p} cannot be executed ({e}); re-run ./setup.sh on this machine")
    print("ready" if ok else "NOT READY: fix the items marked MISS/BAD")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
