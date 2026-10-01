#!/usr/bin/env bash
# One-time setup for the PROBA v3.4 benchmark.
# Supports macOS (Apple Silicon / Intel) and Linux (x86-64 / arm64).
#
#   ./setup.sh                    # auto-selects python3.13 > 3.12 > 3.11 > 3.10 > python3
#   PYTHON=python3.13 ./setup.sh  # force an interpreter
#
# Creates ./.venv (Homebrew Python refuses system-wide pip installs, PEP 668) and
# installs anvil (Foundry), solc 0.8.28 and kubo 0.38.1 into ~/.proba-tools/bin.
set -euo pipefail
cd "$(dirname "$0")"
PREFIX="${PREFIX:-$HOME/.proba-tools}"
BIN="$PREFIX/bin"
mkdir -p "$BIN"

OS="$(uname -s)"; ARCH="$(uname -m)"
case "$OS/$ARCH" in
  Darwin/arm64)          FOUNDRY=darwin_arm64; KUBO=darwin-arm64; SOLC=solc-macos ;;
  Darwin/x86_64)         FOUNDRY=darwin_amd64; KUBO=darwin-amd64; SOLC=solc-macos ;;
  Linux/x86_64)          FOUNDRY=linux_amd64;  KUBO=linux-amd64;  SOLC=solc-static-linux ;;
  Linux/aarch64|Linux/arm64) FOUNDRY=linux_arm64; KUBO=linux-arm64; SOLC="" ;;
  *) echo "unsupported platform $OS/$ARCH"; exit 1 ;;
esac
echo "platform: $OS/$ARCH"

# ---------------------------------------------------------------- Python
if [ -z "${PYTHON:-}" ]; then
  for c in python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v "$c" >/dev/null 2>&1; then PYTHON="$c"; break; fi
  done
fi
PYVER="$("$PYTHON" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
echo "python : $PYTHON ($PYVER)"
case "$PYVER" in 3.8|3.9) echo "Python >= 3.10 is required"; exit 1 ;; esac
if [ "$PYVER" = "3.14" ]; then
  echo "note   : coincurve 21.0.0 publishes no CPython 3.14 wheels. For the fastest wallet"
  echo "         signatures install Python 3.13 (e.g. 'brew install python@3.13') and re-run"
  echo "         with PYTHON=python3.13 ./setup.sh; otherwise a source build is attempted and,"
  echo "         if it fails, the cryptography-based fallback is used."
fi

"$PYTHON" -m venv .venv
# shellcheck disable=SC1091
. .venv/bin/activate
python -m pip install --upgrade pip >/dev/null
python -m pip install -r requirements.txt
if ! python -c "import coincurve" >/dev/null 2>&1; then
  echo "trying to build coincurve from source (needs Xcode Command Line Tools / a C compiler) ..."
  if python -m pip install "coincurve==21.0.0" > .coincurve-build.log 2>&1; then
    echo "coincurve built from source"
  else
    echo "coincurve could not be built (details: .coincurve-build.log) -> fallback wallet backend"
  fi
fi

# ---------------------------------------------------------------- tools
fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }
if [ ! -x "$BIN/anvil" ] || ! "$BIN/anvil" --version >/dev/null 2>&1; then
  fetch "https://github.com/foundry-rs/foundry/releases/download/stable/foundry_stable_${FOUNDRY}.tar.gz" /tmp/foundry.tgz
  tar xzf /tmp/foundry.tgz -C "$BIN"
fi
if [ ! -x "$BIN/solc" ] || ! "$BIN/solc" --version >/dev/null 2>&1; then
  if [ -n "$SOLC" ]; then
    fetch "https://github.com/ethereum/solidity/releases/download/v0.8.28/$SOLC" "$BIN/solc"
    chmod +x "$BIN/solc"
  else
    echo "no official solc 0.8.28 binary for $OS/$ARCH: install solc 0.8.28 and put it on PATH"
  fi
fi
if [ ! -x "$BIN/ipfs" ] || ! "$BIN/ipfs" --version >/dev/null 2>&1; then
  fetch "https://github.com/ipfs/kubo/releases/download/v0.38.1/kubo_v0.38.1_${KUBO}.tar.gz" /tmp/kubo.tgz
  rm -rf /tmp/kubo && tar xzf /tmp/kubo.tgz -C /tmp && cp /tmp/kubo/ipfs "$BIN/ipfs"
fi
if [ "$OS" = "Darwin" ]; then   # binaries fetched by a browser may carry the quarantine flag
  xattr -d com.apple.quarantine "$BIN"/* 2>/dev/null || true
fi

export PATH="$BIN:$PATH"
python bench/check_env.py
echo
echo "Done. Run the benchmark with:  ./run_all.sh"
