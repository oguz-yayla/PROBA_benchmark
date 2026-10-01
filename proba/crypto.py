"""
Core algebra, canonical encodings and domain-separated hashes for PROBA v3.4.

Algebraic setting (Section 3.3 of the paper): a single Type-III BLS12-381
pairing setting.  G1, G2 have prime order R; the ballot-encryption group is
G_E = G1 with a domain-separated generator g_E.

Canonical wire encoding = EIP-2537 encoding, so that the *same bytes* are
(i) hashed into the IPFS content identifier, (ii) sent as transaction
calldata, and (iii) consumed directly by the BLS12-381 precompiles of an
Ethereum-compatible (Prague / EIP-2537) execution layer:
    G1 point : 128 bytes = pad16 || x(48) || pad16 || y(48)
    G2 point : 256 bytes = x.c0 || x.c1 || y.c0 || y.c1  (each 64-byte padded)
    scalar   :  32 bytes big-endian
    identity :  all-zero encoding
"""
from __future__ import annotations

import hashlib
import secrets
from typing import Iterable, Sequence

from Crypto.Hash import keccak as _keccak
import py_arkworks_bls12381 as ark

G1 = ark.G1Point
G2 = ark.G2Point
GT = ark.GT
Scalar = ark.Scalar

# Order of G1, G2, GT (BLS12-381 "r").
R = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
R2_256 = pow(2, 256, R)          # used by the on-chain wide reduction
PROTOCOL_VERSION = b"PROBA-v3.4"


# --------------------------------------------------------------------------
# Hashes
# --------------------------------------------------------------------------
def keccak256(data: bytes) -> bytes:
    h = _keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


def tag(name: str) -> bytes:
    """32-byte domain-separation tag: keccak256("PROBA-v3.4/<name>")."""
    return keccak256(PROTOCOL_VERSION + b"/" + name.encode())


TAG_ATTR = tag("attr")          # H_attr
TAG_ISS = tag("fs/issue")       # pi_iss
TAG_BAL01 = tag("fs/ballot01")  # per-candidate disjunctive proof
TAG_BALSUM = tag("fs/ballotsum")  # one-selection proof
TAG_DEC = tag("fs/decrypt")     # correct partial decryption
TAG_KEY = tag("fs/keyposs")     # key possession
TAG_SIG = keccak256(PROTOCOL_VERSION)  # statement tag in M_v
DST_H1 = b"PROBA-v3.4_TIAC_H1_BLS12381G1_XMD:SHA-256_SSWU_RO_"
DST_GEN = b"PROBA-v3.4_GEN_BLS12381G1_XMD:SHA-256_SSWU_RO_"


def hash_to_scalar(tag32: bytes, data: bytes) -> int:
    """Wide (512-bit) reduction so that the result is statistically uniform.

    d  = keccak256(tag || data)
    hi = keccak256(d || 0x00), lo = keccak256(d || 0x01)
    out = (hi * 2^256 + lo) mod R
    The Solidity contract implements exactly the same function with
    addmod(mulmod(hi, 2^256 mod R, R), lo mod R, R).
    """
    d = keccak256(tag32 + data)
    hi = int.from_bytes(keccak256(d + b"\x00"), "big")
    lo = int.from_bytes(keccak256(d + b"\x01"), "big")
    return (hi * (1 << 256) + lo) % R


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# --------------------------------------------------------------------------
# Scalars
# --------------------------------------------------------------------------
def rand_scalar() -> int:
    while True:
        x = secrets.randbelow(R)
        if x:
            return x


def S(x: int) -> Scalar:
    return Scalar.from_be_bytes_mod_order((x % R).to_bytes(32, "big"))


def inv(x: int) -> int:
    return pow(x, R - 2, R)


def lagrange_at_zero(indices: Sequence[int]) -> list[int]:
    out = []
    for i in indices:
        num, den = 1, 1
        for j in indices:
            if j != i:
                num = num * (-j) % R
                den = den * (i - j) % R
        out.append(num * inv(den) % R)
    return out


# --------------------------------------------------------------------------
# Group helpers
# --------------------------------------------------------------------------
g1 = G1()          # standard generator of G1
g2 = G2()          # standard generator of G2
ID1 = G1.identity()
ID2 = G2.identity()
# Nothing-up-my-sleeve bases (RFC 9380 hash-to-curve).  Nobody may know
# log_g1(h1): with a known logarithm, two requests sharing one commitment C
# yield h^y and hence credentials on arbitrary attributes (see tests).
h1 = G1.hash_to_curve(DST_GEN, b"h1")   # Pedersen second base for C
gE = G1.hash_to_curve(DST_GEN, b"gE")   # ElGamal generator g_E


def mul1(P: G1, k: int) -> G1:
    return P * S(k)


def mul2(P: G2, k: int) -> G2:
    return P * S(k)


def msm1(points: Sequence[G1], scalars: Sequence[int]) -> G1:
    return G1.multiexp_unchecked(list(points), [S(k) for k in scalars])


def msm2(points: Sequence[G2], scalars: Sequence[int]) -> G2:
    return G2.multiexp_unchecked(list(points), [S(k) for k in scalars])


def pairing_check(g1s: Sequence[G1], g2s: Sequence[G2]) -> bool:
    return GT.pairing_check(list(g1s), list(g2s))


# --------------------------------------------------------------------------
# EIP-2537 canonical encodings
# --------------------------------------------------------------------------
_PAD = b"\x00" * 16


def enc1(P: G1) -> bytes:
    b = P.to_xy_bytes_be()
    return _PAD + b[:48] + _PAD + b[48:]


def dec1(b: bytes) -> G1:
    assert len(b) == 128 and b[:16] == _PAD and b[64:80] == _PAD
    if b == bytes(128):
        return G1.identity()
    P = G1.from_xy_bytes_be(b[16:64] + b[80:128])
    if not P.is_in_subgroup():
        raise ValueError("G1 point not in subgroup")
    return P


def enc2(P: G2) -> bytes:
    b = P.to_xy_bytes_be()  # x.c0 x.c1 y.c0 y.c1, 48 bytes each
    return b"".join(_PAD + b[i:i + 48] for i in range(0, 192, 48))


def dec2(b: bytes) -> G2:
    assert len(b) == 256
    if b == bytes(256):
        return G2.identity()
    raw = b"".join(b[i + 16:i + 64] for i in range(0, 256, 64))
    P = G2.from_xy_bytes_be(raw)
    if not P.is_in_subgroup():
        raise ValueError("G2 point not in subgroup")
    return P


def encS(x: int) -> bytes:
    return (x % R).to_bytes(32, "big")


def decS(b: bytes) -> int:
    x = int.from_bytes(b, "big")
    if x >= R:
        raise ValueError("non-canonical scalar")
    return x


def u256(x: int) -> bytes:
    return x.to_bytes(32, "big")


# Compressed (ZCash) sizes, reported for storage-size comparison only.
def comp1(P: G1) -> bytes:
    return P.to_compressed_bytes()


def comp2(P: G2) -> bytes:
    return P.to_compressed_bytes()


def concat(parts: Iterable[bytes]) -> bytes:
    return b"".join(parts)
