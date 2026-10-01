"""
Helios-style threshold exponential ElGamal in G_E = G1 (BLS12-381) with
Chaum--Pedersen proofs, bound by Fiat--Shamir to (eid, pk_v, seq_v, ct_v).

Per candidate j:   ct_j = (A_j, B_j) = (r_j g_E, v_j g_E + r_j Y),  v_j in {0,1}
Ballot validity :  disjunctive CP proof (c0, c1, z0, z1) that v_j in {0,1}
One selection   :  CP proof (c, z) that sum_j v_j = 1 on the product ciphertext
Decryption      :  delta_{i,j} = sk_i A_j with CP proof log_gE(Y_i) = log_Aj(delta)
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from .crypto import (G1, R, gE, ID1, S, TAG_BAL01, TAG_BALSUM, TAG_DEC, TAG_KEY,
                     enc1, encS, u256, keccak256, hash_to_scalar, rand_scalar,
                     mul1, msm1, lagrange_at_zero, concat)


# --------------------------------------------------------------------------
# Trustee key generation (joint-Feldman DKG) and key-possession proofs
# --------------------------------------------------------------------------
@dataclass
class TrusteeKey:
    index: int
    sk: int
    Y: G1         # share public key  Y_i = sk_i g_E
    pop: tuple    # Schnorr proof of possession (c, z)


def _poly_eval(coeffs, x):
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % R
    return acc


def prove_key(eid: bytes, i: int, sk: int, Y: G1):
    w = rand_scalar()
    T = mul1(gE, w)
    c = hash_to_scalar(TAG_KEY, eid + u256(i) + enc1(Y) + enc1(T))
    return c, (w + c * sk) % R


def verify_key(eid: bytes, i: int, Y: G1, pop) -> bool:
    c, z = pop
    T = msm1([gE, Y], [z, R - c])
    return c == hash_to_scalar(TAG_KEY, eid + u256(i) + enc1(Y) + enc1(T))


def trustee_dkg(eid: bytes, n: int, t: int):
    deals = []
    for _ in range(n):
        f = [rand_scalar() for _ in range(t)]
        deals.append((f, [mul1(gE, a) for a in f]))
    keys = []
    for i in range(1, n + 1):
        powers = [pow(i, k, R) for k in range(t)]
        ski = 0
        for f, Cm in deals:
            si = _poly_eval(f, i)
            assert mul1(gE, si) == msm1(Cm, powers)   # Feldman share check
            ski = (ski + si) % R
        Yi = mul1(gE, ski)
        keys.append(TrusteeKey(i, ski, Yi, prove_key(eid, i, ski, Yi)))
    mpk = ID1
    for _, Cm in deals:
        mpk = mpk + Cm[0]
    return keys, mpk


# --------------------------------------------------------------------------
# Ballot encryption and proofs
# --------------------------------------------------------------------------
@dataclass
class EncBallot:
    A: list      # list[G1]
    B: list      # list[G1]
    r: list      # encryption randomness (voter secret; revealed only on audit)

    def ct_bytes(self) -> bytes:
        return concat(enc1(a) + enc1(b) for a, b in zip(self.A, self.B))


@dataclass
class BallotProof:
    per: list    # list[(c0, c1, z0, z1)]
    sum: tuple   # (c, z)

    def to_bytes(self) -> bytes:
        out = [concat(encS(v) for v in p) for p in self.per]
        out.append(encS(self.sum[0]) + encS(self.sum[1]))
        return concat(out)


def encrypt(Y: G1, vote: list[int]) -> EncBallot:
    A, B, rs = [], [], []
    for v in vote:
        r = rand_scalar()
        A.append(mul1(gE, r))
        B.append(msm1([gE, Y], [v, r]))
        rs.append(r)
    return EncBallot(A, B, rs)


def ctx_prefix(eid: bytes, pk: bytes, seq: int, ct_bytes: bytes) -> bytes:
    """eid || pk || seq || keccak(ct_v): binds every proof to its context."""
    return eid + pk + u256(seq) + keccak256(ct_bytes)


def _ch01(prefix, j, A, B, a0, b0, a1, b1):
    return hash_to_scalar(TAG_BAL01, prefix + u256(j) + enc1(A) + enc1(B)
                          + enc1(a0) + enc1(b0) + enc1(a1) + enc1(b1))


def prove_01(prefix: bytes, j: int, Y: G1, A: G1, B: G1, v: int, r: int):
    """Disjunctive CP proof that (A, B) encrypts v in {0,1}."""
    k = 1 - v                           # simulated branch
    ck, zk = rand_scalar(), rand_scalar()
    ak = msm1([gE, A], [zk, R - ck])
    # b_k = Y^{z_k} (B / g^k)^{-c_k} = Y^{z_k} B^{-c_k} g^{k c_k}
    bk = msm1([Y, B, gE], [zk, R - ck, (k * ck) % R])
    w = rand_scalar()
    av, bv = mul1(gE, w), mul1(Y, w)
    if v == 0:
        a0, b0, a1, b1 = av, bv, ak, bk
    else:
        a0, b0, a1, b1 = ak, bk, av, bv
    c = _ch01(prefix, j, A, B, a0, b0, a1, b1)
    cv = (c - ck) % R
    zv = (w + cv * r) % R
    return (cv, ck, zv, zk) if v == 0 else (ck, cv, zk, zv)


def verify_01(prefix: bytes, j: int, Y: G1, A: G1, B: G1, p) -> bool:
    c0, c1, z0, z1 = p
    a0 = msm1([gE, A], [z0, R - c0])
    b0 = msm1([Y, B], [z0, R - c0])
    a1 = msm1([gE, A], [z1, R - c1])
    b1 = msm1([Y, B, gE], [z1, R - c1, c1])
    return (c0 + c1) % R == _ch01(prefix, j, A, B, a0, b0, a1, b1)


def _chsum(prefix, SA, SB, a, b):
    return hash_to_scalar(TAG_BALSUM, prefix + enc1(SA) + enc1(SB) + enc1(a) + enc1(b))


def prove_sum(prefix: bytes, Y: G1, SA: G1, SB: G1, Rsum: int, total: int = 1):
    """CP proof that the product ciphertext encrypts `total` (=1)."""
    w = rand_scalar()
    a, b = mul1(gE, w), mul1(Y, w)
    c = _chsum(prefix, SA, SB, a, b)
    return c, (w + c * Rsum) % R


def verify_sum(prefix: bytes, Y: G1, SA: G1, SB: G1, p, total: int = 1) -> bool:
    c, z = p
    a = msm1([gE, SA], [z, R - c])
    b = msm1([Y, SB, gE], [z, R - c, (c * total) % R])
    return c == _chsum(prefix, SA, SB, a, b)


def prove_ballot(eid, pk, seq, Y, eb: EncBallot, vote) -> BallotProof:
    prefix = ctx_prefix(eid, pk, seq, eb.ct_bytes())
    per = [prove_01(prefix, j, Y, eb.A[j], eb.B[j], vote[j], eb.r[j]) for j in range(len(vote))]
    SA, SB = _sum(eb.A), _sum(eb.B)
    return BallotProof(per, prove_sum(prefix, Y, SA, SB, sum(eb.r) % R))


def verify_ballot(eid, pk, seq, Y, A: list, B: list, pf: BallotProof, ct_bytes=None) -> bool:
    if ct_bytes is None:
        ct_bytes = concat(enc1(a) + enc1(b) for a, b in zip(A, B))
    prefix = ctx_prefix(eid, pk, seq, ct_bytes)
    for j in range(len(A)):
        if not verify_01(prefix, j, Y, A[j], B[j], pf.per[j]):
            return False
    return verify_sum(prefix, Y, _sum(A), _sum(B), pf.sum)


def _sum(points):
    acc = ID1
    for P in points:
        acc = acc + P
    return acc


def benaloh_audit(Y: G1, eb: EncBallot, claimed_vote: list[int]) -> bool:
    """Cast-as-intended challenge: re-encrypt with revealed randomness."""
    for A, B, r, v in zip(eb.A, eb.B, eb.r, claimed_vote):
        if A != mul1(gE, r) or B != msm1([gE, Y], [v, r]):
            return False
    return True


# --------------------------------------------------------------------------
# Tally: aggregation, partial decryption, combination, bounded discrete log
# --------------------------------------------------------------------------
def aggregate(ballots: list[tuple[list, list]]):
    nc = len(ballots[0][0])
    SA, SB = [ID1] * nc, [ID1] * nc
    for A, B in ballots:
        for j in range(nc):
            SA[j] = SA[j] + A[j]
            SB[j] = SB[j] + B[j]
    return SA, SB


def _chdec(eid, i, j, Yi, A, d, t1, t2):
    return hash_to_scalar(TAG_DEC, eid + u256(i) + u256(j) + enc1(Yi) + enc1(A) + enc1(d)
                          + enc1(t1) + enc1(t2))


def pardec_only(key: TrusteeKey, A: G1) -> G1:
    return mul1(A, key.sk)


def prove_dec(eid: bytes, key: TrusteeKey, A: G1, j: int, d: G1):
    w = rand_scalar()
    t1, t2 = mul1(gE, w), mul1(A, w)
    c = _chdec(eid, key.index, j, key.Y, A, d, t1, t2)
    return c, (w + c * key.sk) % R


def partial_decrypt(eid: bytes, key: TrusteeKey, A: G1, j: int):
    d = pardec_only(key, A)
    return d, prove_dec(eid, key, A, j, d)


def verify_partial(eid: bytes, i: int, Yi: G1, A: G1, j: int, d: G1, pf) -> bool:
    c, z = pf
    t1 = msm1([gE, Yi], [z, R - c])
    t2 = msm1([A, d], [z, R - c])
    return c == _chdec(eid, i, j, Yi, A, d, t1, t2)


class DLog:
    """Baby-step giant-step for tallies in [0, bound]."""

    def __init__(self, bound: int):
        self.m = max(1, math.isqrt(bound) + 1)
        self.table = {}
        P = ID1
        for k in range(self.m):
            self.table[enc1(P)] = k
            P = P + gE
        self.giant = -mul1(gE, self.m)
        self.bound = bound

    def solve(self, M: G1) -> int:
        P = M
        for i in range(self.m + 1):
            k = self.table.get(enc1(P))
            if k is not None:
                return i * self.m + k
            P = P + self.giant
        raise ValueError("tally out of declared bound")


def combine(SB_j: G1, partials: dict, dlog: DLog) -> int:
    """partials: trustee index -> delta_{i,j}."""
    idx = sorted(partials)
    lag = lagrange_at_zero(idx)
    D = msm1([partials[i] for i in idx], lag)
    return dlog.solve(SB_j - D)
