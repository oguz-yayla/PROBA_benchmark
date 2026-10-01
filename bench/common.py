"""Timing, statistics, environment capture and result persistence."""
from __future__ import annotations

import csv
import gc
import json
import math
import os
import platform
import statistics
import subprocess
import sys
import time
from importlib import metadata
from pathlib import Path

from scipy import stats as _st

ROOT = Path(__file__).resolve().parent.parent
RESULTS = Path(os.environ.get("PROBA_RESULTS", ROOT / "results"))
RAW = RESULTS / "raw"
RESULTS.mkdir(parents=True, exist_ok=True)
RAW.mkdir(parents=True, exist_ok=True)

QUICK = os.environ.get("PROBA_QUICK") == "1"


def reps(n: int) -> int:
    return max(5, n // 10) if QUICK else n


def measure(fn, n: int, warmup: int = 5, setup=None):
    """Run fn n times (after warm-up), return samples in milliseconds.

    If `setup` is given, it is called before every repetition (untimed) and
    its return value is passed to fn.  GC is disabled while timing.
    """
    n = reps(n)
    for _ in range(warmup):
        fn(setup()) if setup else fn()
    out = []
    gc.collect()
    gc.disable()
    try:
        for _ in range(n):
            if setup:
                arg = setup()
                t0 = time.perf_counter_ns(); fn(arg); t1 = time.perf_counter_ns()
            else:
                t0 = time.perf_counter_ns(); fn(); t1 = time.perf_counter_ns()
            out.append((t1 - t0) / 1e6)
    finally:
        gc.enable()
    return out


def summarize(samples):
    n = len(samples)
    mean = statistics.fmean(samples)
    sd = statistics.stdev(samples) if n > 1 else 0.0
    s = sorted(samples)
    q = lambda p: s[min(n - 1, max(0, int(math.ceil(p * n)) - 1))]
    half = _st.t.ppf(0.975, n - 1) * sd / math.sqrt(n) if n > 1 else 0.0
    return dict(n=n, mean=mean, sd=sd, median=statistics.median(s), p5=q(0.05), p95=q(0.95),
                min=s[0], max=s[-1], ci95_lo=mean - half, ci95_hi=mean + half)


def save_raw(name: str, rows: dict):
    """rows: label -> list of samples."""
    p = RAW / f"{name}.csv"
    with p.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["label", "rep", "ms"])
        for k, v in rows.items():
            for i, x in enumerate(v):
                w.writerow([k, i, f"{x:.6f}"])
    return p


def save_json(name: str, obj):
    p = RESULTS / f"{name}.json"
    p.write_text(json.dumps(obj, indent=2, default=str))
    return p


def _ver(pkg):
    try:
        return metadata.version(pkg)
    except Exception:
        return "n/a"


def _sysctl(key):
    try:
        return subprocess.run(["sysctl", "-n", key], capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:
        return ""


def environment(extra: dict | None = None):
    cpu, mem = platform.processor() or platform.machine(), "unknown"
    if sys.platform == "darwin":
        cpu = _sysctl("machdep.cpu.brand_string") or cpu
        try:
            mem = f"{int(_sysctl('hw.memsize')) / 2 ** 30:.1f} GiB"
        except ValueError:
            pass
        perf = _sysctl("hw.perflevel0.physicalcpu")
        eff = _sysctl("hw.perflevel1.physicalcpu")
        if perf:
            cpu += f" ({perf} performance + {eff or 0} efficiency cores)"
    else:
        try:
            for line in open("/proc/cpuinfo"):
                if line.startswith("model name"):
                    cpu = line.split(":", 1)[1].strip(); break
        except OSError:
            pass
        try:
            for line in open("/proc/meminfo"):
                if line.startswith("MemTotal"):
                    mem = f"{int(line.split()[1]) / 1024 / 1024:.1f} GiB"; break
        except OSError:
            pass
    from proba.ballot import WALLET_BACKEND
    env = dict(
        cpu=cpu, machine=platform.machine(), logical_cpus=os.cpu_count(), memory=mem,
        os=f"{platform.system()} {platform.release()}", distro=_distro(),
        python=sys.version.split()[0],
        py_arkworks_bls12381=_ver("py_arkworks_bls12381"), coincurve=_ver("coincurve"),
        pycryptodome=_ver("pycryptodome"), cryptography=_ver("cryptography"), web3=_ver("web3"),
        wallet_backend=WALLET_BACKEND,
        quick_mode=QUICK, timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )
    if extra:
        env.update(extra)
    return env


def _distro():
    if sys.platform == "darwin":
        v = platform.mac_ver()[0]
        return f"macOS {v}" if v else "macOS"
    try:
        for line in open("/etc/os-release"):
            if line.startswith("PRETTY_NAME"):
                return line.split("=", 1)[1].strip().strip('"')
    except Exception:
        return "n/a"


def tool_version(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout.strip().splitlines()[0]
    except Exception:
        return "n/a"
