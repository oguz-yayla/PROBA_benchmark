"""
Fallback secp256k1 backend, used only when `coincurve` is not installable
(e.g. CPython 3.14 on macOS arm64, for which coincurve 21.0.0 ships no wheel).

* key generation and ECDSA signing use `cryptography` (OpenSSL, native code);
* the Ethereum recovery id v and the ecrecover-equivalent verification are
  computed in pure Python (Jacobian coordinates), so results are bit-exact
  with the contract's `ecrecover`, but T_Sign / T_SigVr are slower than with
  libsecp256k1.  The active backend is recorded in every results/*.json.
"""
from __future__ import annotations

import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

P = 2**256 - 2**32 - 977          # secp256k1 field prime
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
assert (GY * GY - GX ** 3 - 7) % P == 0 and N.bit_length() == 256   # constant sanity check


# --------------------------------------------------------------------------
# Jacobian arithmetic on y^2 = x^3 + 7
# --------------------------------------------------------------------------
def _dbl(p):
    X, Y, Z = p
    if Y == 0:
        return (0, 1, 0)
    YY = Y * Y % P
    S = 4 * X * YY % P
    M = 3 * X * X % P
    X3 = (M * M - 2 * S) % P
    return (X3, (M * (S - X3) - 8 * YY * YY) % P, 2 * Y * Z % P)


def _add(p, q):
    if p[2] == 0:
        return q
    if q[2] == 0:
        return p
    X1, Y1, Z1 = p
    X2, Y2, Z2 = q
    Z1Z1, Z2Z2 = Z1 * Z1 % P, Z2 * Z2 % P
    U1, U2 = X1 * Z2Z2 % P, X2 * Z1Z1 % P
    S1, S2 = Y1 * Z2 * Z2Z2 % P, Y2 * Z1 * Z1Z1 % P
    if U1 == U2:
        return _dbl(p) if S1 == S2 else (0, 1, 0)
    H, R = (U2 - U1) % P, (S2 - S1) % P
    HH = H * H % P
    HHH = H * HH % P
    V = U1 * HH % P
    X3 = (R * R - HHH - 2 * V) % P
    return (X3, (R * (V - X3) - S1 * HHH) % P, H * Z1 * Z2 % P)


def _affine(p):
    if p[2] == 0:
        return None
    zi = pow(p[2], P - 2, P)
    zi2 = zi * zi % P
    return (p[0] * zi2 % P, p[1] * zi2 * zi % P)


def _double_mul(a, A, b, B):
    """a*A + b*B (Shamir's trick), affine inputs, Jacobian output."""
    J = lambda Q: (Q[0], Q[1], 1)
    AB = _add(J(A), J(B))
    acc = (0, 1, 0)
    for i in range(max(a.bit_length(), b.bit_length()) - 1, -1, -1):
        acc = _dbl(acc)
        ba, bb = (a >> i) & 1, (b >> i) & 1
        if ba and bb:
            acc = _add(acc, AB)
        elif ba:
            acc = _add(acc, J(A))
        elif bb:
            acc = _add(acc, J(B))
    return acc


def recover(digest: bytes, r: int, s: int, recid: int):
    """ecrecover: returns the 64-byte public key or None."""
    if not (0 < r < N and 0 < s < N) or recid not in (0, 1):
        return None
    x = r
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if y * y % P != y2:
        return None
    if (y & 1) != recid:
        y = P - y
    e = int.from_bytes(digest, "big") % N
    ri = pow(r, N - 2, N)
    Q = _affine(_double_mul((-e * ri) % N, (GX, GY), (s * ri) % N, (x, y)))
    if Q is None:
        return None
    return Q[0].to_bytes(32, "big") + Q[1].to_bytes(32, "big")


# --------------------------------------------------------------------------
# Key and signature API used by proba.ballot
# --------------------------------------------------------------------------
class PrivateKey:
    def __init__(self, secret: bytes | None = None):
        if secret is None:
            while True:
                k = secrets.randbelow(N)
                if k:
                    break
            secret = k.to_bytes(32, "big")
        self.secret = secret
        self._key = ec.derive_private_key(int.from_bytes(secret, "big"), ec.SECP256K1())
        nums = self._key.public_key().public_numbers()
        self.pk = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")

    def sign_recoverable(self, digest: bytes):
        """Returns (r, s, recid) with low-s normalisation, as libsecp256k1."""
        der = self._key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        r, s = utils.decode_dss_signature(der)
        if s > N // 2:
            s = N - s
        for recid in (0, 1):
            if recover(digest, r, s, recid) == self.pk:
                return r.to_bytes(32, "big"), s.to_bytes(32, "big"), recid
        raise RuntimeError("recovery id not found")
