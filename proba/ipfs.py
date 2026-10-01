"""
Local IPFS (kubo) node used as the pinning service of Algorithm 7 step 4.

The node runs in --offline mode on localhost: add/pin/cat latencies measure
the local content-addressed store only (no DHT, no WAN transfer).
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import tempfile
import time

import requests

from .chain import find_tool

IPFS = os.environ.get("IPFS_BIN") or find_tool("ipfs", "/opt")


def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


class IpfsNode:
    def __init__(self):
        self.repo = tempfile.mkdtemp(prefix="proba-ipfs-")
        env = dict(os.environ, IPFS_PATH=self.repo)
        self.env = env
        run = lambda *a: subprocess.run([IPFS, *a], env=env, check=True, capture_output=True)
        run("init", "--profile", "test,lowpower")
        self.api, gw = _free_port(), _free_port()
        run("config", "Addresses.API", f"/ip4/127.0.0.1/tcp/{self.api}")
        run("config", "Addresses.Gateway", f"/ip4/127.0.0.1/tcp/{gw}")
        run("config", "--json", "Routing.Type", '"none"')
        self.proc = subprocess.Popen([IPFS, "daemon", "--offline"], env=env,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.url = f"http://127.0.0.1:{self.api}/api/v0"
        self.s = requests.Session()
        for _ in range(300):
            try:
                self.s.post(self.url + "/version", timeout=1); break
            except Exception:
                time.sleep(0.1)

    def version(self) -> str:
        return self.s.post(self.url + "/version").json()["Version"]

    def add(self, data: bytes) -> str:
        r = self.s.post(self.url + "/add", params={"cid-version": 1, "raw-leaves": "true", "pin": "true",
                                                   "quieter": "true"},
                        files={"file": ("b", data)})
        return r.json()["Hash"]

    def cat(self, cid: str) -> bytes:
        return self.s.post(self.url + "/cat", params={"arg": cid}).content

    def close(self):
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except Exception:
            self.proc.kill()
        shutil.rmtree(self.repo, ignore_errors=True)
