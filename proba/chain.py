"""
Execution-layer driver.

Starts a local Foundry `anvil` node with the Prague hardfork (EIP-2537
BLS12-381 precompiles, EIP-7623 calldata pricing), a zero base fee and zero
gas price -- i.e. the "consortium subsidises voter transactions" policy of
Definition 3.4 -- compiles the contracts with solc and submits transactions
*from the voters' own, unfunded election wallets*.

NOTE: anvil is a single-node development chain with instant sealing.  It
measures EVM gas and state transitions exactly, but it does NOT model IBFT
consensus, validator networking or finality latency.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

from eth_account import Account
from web3 import Web3
from web3.logs import DISCARD

from .crypto import enc1, enc2, g2, gE
from . import ballot as BL


def find_tool(name: str, *extra: str) -> str:
    """$NAME env var > PATH > ~/.proba-tools/bin > extra locations."""
    env = os.environ.get(name.upper())
    if env:
        return env
    p = shutil.which(name)
    if p:
        return p
    for d in (os.path.expanduser("~/.proba-tools/bin"), *extra):
        c = os.path.join(d, name)
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return name


ROOT = Path(__file__).resolve().parent.parent
SOLC = find_tool("solc", "/opt")
ANVIL = find_tool("anvil", "/opt/foundry")
SOLC_FLAGS = ["--via-ir", "--optimize", "--optimize-runs", "200", "--evm-version", "cancun"]


def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


class Node:
    def __init__(self, gas_limit: int = 1_000_000_000):
        self.port = _free_port()
        self.proc = subprocess.Popen(
            [ANVIL, "--hardfork", "prague", "--port", str(self.port), "--silent",
             "--gas-limit", str(gas_limit), "--block-base-fee-per-gas", "0", "--gas-price", "0",
             "--accounts", "2"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.w3 = Web3(Web3.HTTPProvider(f"http://127.0.0.1:{self.port}", request_kwargs={"timeout": 120}))
        for _ in range(100):
            try:
                if self.w3.is_connected():
                    break
            except Exception:
                pass
            time.sleep(0.1)
        self.deployer = self.w3.eth.accounts[0]
        self.chain_id = self.w3.eth.chain_id

    def close(self):
        self.proc.terminate()
        try:
            self.proc.wait(5)
        except Exception:
            self.proc.kill()

    def version(self) -> str:
        return self.w3.client_version


def compile_contracts():
    out = subprocess.run(
        [SOLC, *SOLC_FLAGS, "--combined-json", "abi,bin,bin-runtime",
         str(ROOT / "contracts/ProbaElection.sol"), str(ROOT / "contracts/PerezCeesayElection.sol")],
        check=True, capture_output=True, text=True).stdout
    d = json.loads(out)["contracts"]
    res = {}
    for k, v in d.items():
        name = k.split(":")[1]
        abi = v["abi"] if isinstance(v["abi"], list) else json.loads(v["abi"])
        res[name] = dict(abi=abi, bin=v["bin"], runtime=len(v["bin-runtime"]) // 2)
    return res


def solc_version() -> str:
    return subprocess.run([SOLC, "--version"], capture_output=True, text=True).stdout.strip().splitlines()[-1]


def params_blob(Y, mvk) -> bytes:
    return enc1(gE) + enc1(Y) + enc2(-g2) + enc2(mvk.alpha) + enc2(mvk.beta2)


class ProbaContract:
    def __init__(self, node: Node, art, eid, nc, Y, mvk, cfg):
        w3 = node.w3
        C = w3.eth.contract(abi=art["abi"], bytecode=art["bin"])
        txh = C.constructor(eid, nc, cfg, params_blob(Y, mvk)).transact({"from": node.deployer})
        rc = w3.eth.wait_for_transaction_receipt(txh, poll_latency=0.002)
        self.deploy_gas = rc.gasUsed
        self.c = w3.eth.contract(address=rc.contractAddress, abi=art["abi"])
        self.node = node

    def _send(self, wallet: BL.Wallet, fn):
        w3 = self.node.w3
        addr = Web3.to_checksum_address(wallet.address)
        tx = fn.build_transaction({"from": addr, "nonce": w3.eth.get_transaction_count(addr),
                                   "gas": 30_000_000, "gasPrice": 0, "chainId": self.node.chain_id})
        signed = Account.sign_transaction(tx, wallet.secret)
        h = w3.eth.send_raw_transaction(signed.raw_transaction)
        return w3.eth.wait_for_transaction_receipt(h, poll_latency=0.002)

    def cast(self, wallet: BL.Wallet, tx: BL.CastTx, profiled=False):
        r, s, v = tx.tau
        f = self.c.functions.castProfiled if profiled else self.c.functions.cast
        return self._send(wallet, f(tx.B, tx.cid, v, r, s))

    def try_cast(self, wallet, tx: BL.CastTx):
        """eth_call dry-run: returns (accepted, revert reason)."""
        r, s, v = tx.tau
        try:
            self.c.functions.cast(tx.B, tx.cid, v, r, s).call(
                {"from": Web3.to_checksum_address(wallet.address), "gas": 30_000_000})
            return True, "accepted"
        except Exception as e:
            msg = str(e)
            for k in ("C1:", "C2:", "C3:", "C4:", "C5:", "precompile", "g1add"):
                if k in msg:
                    i = msg.index(k)
                    return False, msg[i:i + 16].split("'")[0].split('"')[0].strip(")")
            return False, msg[:60]

    def profile(self, rc):
        ev = self.c.events.GasProfile().process_receipt(rc, errors=DISCARD)[0]["args"]
        return dict(c1=ev.c1, c2=ev.c2, c3=ev.c3, c4=ev.c4, c5=ev.c5store)

    def latest(self, pk: bytes):
        return self.c.functions.latest(BL.keccak256(pk)).call()

    def accepted_events(self):
        return self.c.events.BallotAccepted().get_logs(from_block=0)


class BaselineContract:
    def __init__(self, node: Node, art, eid):
        w3 = node.w3
        C = w3.eth.contract(abi=art["abi"], bytecode=art["bin"])
        rc = w3.eth.wait_for_transaction_receipt(C.constructor(eid).transact({"from": node.deployer}), poll_latency=0.002)
        self.deploy_gas = rc.gasUsed
        self.c = w3.eth.contract(address=rc.contractAddress, abi=art["abi"])
        self.node = node

    def authorize(self, addresses):
        w3 = self.node.w3
        h = self.c.functions.authorize([Web3.to_checksum_address(a) for a in addresses]).transact(
            {"from": self.node.deployer, "gas": 900_000_000})
        return w3.eth.wait_for_transaction_receipt(h, poll_latency=0.002)

    def cast(self, wallet: BL.Wallet, cid: bytes, tau: bytes):
        w3 = self.node.w3
        addr = Web3.to_checksum_address(wallet.address)
        tx = self.c.functions.cast(cid, tau).build_transaction(
            {"from": addr, "nonce": w3.eth.get_transaction_count(addr), "gas": 1_000_000,
             "gasPrice": 0, "chainId": self.node.chain_id})
        signed = Account.sign_transaction(tx, wallet.secret)
        return w3.eth.wait_for_transaction_receipt(w3.eth.send_raw_transaction(signed.raw_transaction), poll_latency=0.002)
