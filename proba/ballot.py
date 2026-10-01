"""
Election wallet (DS), ballot object B_v, content identifier and the public
acceptance predicate Accept (checks C1--C5 of Algorithm 7).

Wallet  : secp256k1 Ethereum account.  pk_v = 64-byte uncompressed key,
          address = keccak(pk_v)[12:].  tau_v = EIP-191 signature on
          keccak(TAG_SIG || eid || pk_v || seq_v || cid_v), verified on-chain
          with ecrecover.
Object  : B_v = A_v || Theta_v, with
          A_v     = eid(32) | pk(64) | T_cred(32) | seq(32) | nc(32) | ct(256 nc)
                    | pi_bal(128 nc + 64)
          Theta_v = h'(128) | s'(128)            (re-randomised credential)
          |B_v| = 512 + 384 nc bytes (EIP-2537 wire encoding)
CID     : CIDv1, codec raw (0x55), multihash sha2-256 -> identical to
          `ipfs add --cid-version=1 --raw-leaves` for single-block objects.
"""
from __future__ import annotations

import base64
import os
from dataclasses import dataclass

# secp256k1 backend: libsecp256k1 via coincurve when available, otherwise the
# cryptography/OpenSSL fallback (identical signatures and recovery, slower).
try:
    if os.environ.get("PROBA_FORCE_FALLBACK") == "1":
        raise ImportError
    import coincurve
    WALLET_BACKEND = f"coincurve {getattr(coincurve, '__version__', '')} (libsecp256k1)".replace("  ", " ")
except ImportError:
    coincurve = None
    from . import secp256k1_fallback as _fb
    WALLET_BACKEND = "cryptography/OpenSSL + pure-Python ecrecover (fallback)"

from .crypto import (keccak256, sha256, u256, enc1, dec1, decS, TAG_SIG, concat)
from . import elgamal as HE
from . import tiac as TIAC

SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


# --------------------------------------------------------------------------
# Wallet
# --------------------------------------------------------------------------
@dataclass
class Wallet:
    sk: object         # backend private-key object
    pk: bytes          # 64 bytes
    address: bytes     # 20 bytes

    @property
    def secret(self) -> bytes:
        return self.sk.secret

    @staticmethod
    def new() -> "Wallet":
        if coincurve is not None:
            sk = coincurve.PrivateKey()
            pk = sk.public_key.format(compressed=False)[1:]
        else:
            sk = _fb.PrivateKey()
            pk = sk.pk
        return Wallet(sk, pk, keccak256(pk)[12:])


def statement_digest(eid: bytes, pk: bytes, seq: int, cid: bytes) -> bytes:
    """keccak(M_v), M_v = (PROBA-v3.4, eid, pk_v, seq_v, cid_v)."""
    return keccak256(TAG_SIG + eid + pk + u256(seq) + cid)


def eth_digest(d: bytes) -> bytes:
    return keccak256(b"\x19Ethereum Signed Message:\n32" + d)


def sign(w: Wallet, eid: bytes, seq: int, cid: bytes):
    digest = eth_digest(statement_digest(eid, w.pk, seq, cid))
    if coincurve is not None:
        sig = w.sk.sign_recoverable(digest, hasher=None)
        r, s, rec = sig[:32], sig[32:64], sig[64]
    else:
        r, s, rec = w.sk.sign_recoverable(digest)
    return r, s, 27 + rec


def verify_sig(pk: bytes, eid: bytes, seq: int, cid: bytes, tau) -> bool:
    """ecrecover-equivalent check (low-s enforced as in the contract)."""
    r, s, v = tau
    if int.from_bytes(s, "big") > SECP_N // 2 or v not in (27, 28):
        return False
    digest = eth_digest(statement_digest(eid, pk, seq, cid))
    if coincurve is None:
        return _fb.recover(digest, int.from_bytes(r, "big"), int.from_bytes(s, "big"), v - 27) == pk
    try:
        pub = coincurve.PublicKey.from_signature_and_message(r + s + bytes([v - 27]), digest, hasher=None)
    except Exception:
        return False
    return pub.format(compressed=False)[1:] == pk


# --------------------------------------------------------------------------
# Ballot object
# --------------------------------------------------------------------------
def a_bytes(eid, pk, t_cred, seq, nc, ct_bytes, pf_bytes) -> bytes:
    return eid + pk + u256(t_cred) + u256(seq) + u256(nc) + ct_bytes + pf_bytes


def cid_digest(B_v: bytes) -> bytes:
    return sha256(B_v)


def cid_string(digest: bytes) -> str:
    raw = bytes([0x01, 0x55, 0x12, 0x20]) + digest
    return "b" + base64.b32encode(raw).decode().lower().rstrip("=")


def object_size(nc: int) -> int:
    return 512 + 384 * nc


def compressed_size(nc: int) -> int:
    """Same content with ZCash-compressed G1 points (48 B)."""
    return 192 + 96 * nc + (128 * nc + 64) + 2 * 48


@dataclass
class CastTx:
    B: bytes
    cid: bytes
    tau: tuple   # (r, s, v)


@dataclass
class Parsed:
    eid: bytes
    pk: bytes
    t_cred: int
    seq: int
    nc: int
    A: list
    Bc: list
    ct_bytes: bytes
    pf: HE.BallotProof
    A_v: bytes
    show: TIAC.Showing


def parse(B: bytes) -> Parsed:
    eid, pk = B[0:32], B[32:96]
    t_cred = int.from_bytes(B[96:128], "big")
    seq = int.from_bytes(B[128:160], "big")
    nc = int.from_bytes(B[160:192], "big")
    if len(B) != object_size(nc):
        raise ValueError("length")
    o = 192
    ct_bytes = B[o:o + 256 * nc]
    A, Bc = [], []
    for j in range(nc):
        A.append(dec1(B[o:o + 128])); Bc.append(dec1(B[o + 128:o + 256])); o += 256
    per = []
    for j in range(nc):
        per.append(tuple(decS(B[o + 32 * k:o + 32 * k + 32]) for k in range(4))); o += 128
    sm = (decS(B[o:o + 32]), decS(B[o + 32:o + 64])); o += 64
    A_v = B[:o]
    hp, sp = dec1(B[o:o + 128]), dec1(B[o + 128:o + 256])
    return Parsed(eid, pk, t_cred, seq, nc, A, Bc, ct_bytes, HE.BallotProof(per, sm), A_v,
                  TIAC.Showing(hp, sp))


def build_ballot(w: Wallet, sigma, mvk, Y, eid: bytes, t_cred: int, seq: int, vote: list[int]):
    """Voter side of Algorithm 7 (steps 1, 3, 4, 5)."""
    nc = len(vote)
    eb = HE.encrypt(Y, vote)
    pf = HE.prove_ballot(eid, w.pk, seq, Y, eb, vote)
    A_v = a_bytes(eid, w.pk, t_cred, seq, nc, eb.ct_bytes(), pf.to_bytes())
    th = TIAC.prove(sigma, mvk, eid, w.pk, t_cred)
    B = A_v + th.to_bytes()
    cid = cid_digest(B)
    tau = sign(w, eid, seq, cid)
    return CastTx(B, cid, tau), eb


# --------------------------------------------------------------------------
# Public acceptance predicate (Python mirror of the contract, Algorithm 7)
# --------------------------------------------------------------------------
S_MAX = 16          # default cap on the sequence number (accepted ballots per wallet)
DELTA_MIN = 60      # default minimum spacing of two accepted ballots of one wallet (s)


class Board:
    """Reference bulletin-board state: Latest[pk] = (seq, cid, tau, t_last)."""

    def __init__(self, eid, nc, Y, mvk, t_open, t_close, s_max=S_MAX, delta_min=DELTA_MIN):
        self.eid, self.nc, self.Y, self.mvk = eid, nc, Y, mvk
        self.t_open, self.t_close = t_open, t_close
        self.s_max, self.delta_min = s_max, delta_min
        self.latest = {}

    def accept(self, tx: CastTx, now: int) -> tuple[bool, str]:
        # C1 (same order as the contract: content identifier first, then decoding)
        if cid_digest(tx.B) != tx.cid:
            return False, "C1:cid"
        try:
            p = parse(tx.B)
        except Exception as e:
            return False, f"C1:parse:{e}"
        if p.eid != self.eid or p.nc != self.nc:
            return False, "C1:context"
        if not (self.t_open <= now <= self.t_close) or now > p.t_cred:
            return False, "C1:time"
        # C2
        if not verify_sig(p.pk, p.eid, p.seq, tx.cid, tx.tau):
            return False, "C2:signature"
        # C3
        if not TIAC.verify(self.mvk, p.eid, p.pk, p.t_cred, p.show):
            return False, "C3:credential"
        # C4
        if not HE.verify_ballot(p.eid, p.pk, p.seq, self.Y, p.A, p.Bc, p.pf, p.ct_bytes):
            return False, "C4:ballot-proof"
        # C5: latest-valid-ballot rule with per-wallet rate limit
        cur = self.latest.get(p.pk)
        if p.seq == 0 or p.seq > self.s_max or (cur is not None and p.seq <= cur[0]):
            return False, "C5:sequence"
        if cur is not None and now < cur[4] + self.delta_min:
            return False, "C5:interval"
        self.latest[p.pk] = (p.seq, tx.cid, tx.tau, tx.B, now)
        return True, "accepted"
