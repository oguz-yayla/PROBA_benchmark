"""
Threshold-issued anonymous credential (modified single-private-attribute
Coconut / TIAC), exactly as specified in Section 3.3.1 of PROBA v3.4.

    m_v   = H_attr(eid || pk_v || T_cred)
    DKG   : x = f_x(0), y = f_y(0);  vk_i = (g2^x_i, g2^y_i, g1^y_i)
    Prep  : C = g1^o h1^m, h = H1(C), D = g1^r h^m, pi_iss
    Issue : c_i = h^x_i D^y_i
    Unbl. : s_i = c_i * beta1_i^{-r},  check e(h, alpha_i beta2_i^m) = e(s_i, g2)
    Aggr. : s = prod s_i^{l_i}
    Show  : Theta = (h', s') = (h^rho, s^rho)
    Verify: h' != 1 and e(h', alpha beta2^m) = e(s', g2)

Because m is recomputed from the public (eid, pk_v, T_cred), the showing
needs no proof of knowledge: v3.2's (kappa, nu, pi_show) hid nothing and did
not bind the ballot (anyone can re-derive them from a public (h', s')).  The
binding of the ballot to the wallet is provided by the wallet signature.

Group operations are written additively in code (P + Q, k * P).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .crypto import (G1, G2, R, g1, g2, h1, ID1, ID2, S, DST_H1, TAG_ATTR,
                     TAG_ISS, enc1, enc2, encS, u256, hash_to_scalar,
                     rand_scalar, mul1, mul2, msm1, msm2, pairing_check,
                     lagrange_at_zero, concat)


# --------------------------------------------------------------------------
# Keys
# --------------------------------------------------------------------------
@dataclass
class IssuerKey:
    index: int
    x: int
    y: int
    alpha: G2
    beta2: G2
    beta1: G1


@dataclass
class MasterVK:
    alpha: G2
    beta2: G2
    beta1: G1
    vks: dict = field(default_factory=dict)   # index -> (alpha_i, beta2_i, beta1_i)


def attr(eid: bytes, pk: bytes, t_cred: int) -> int:
    """m_v = H_attr(enc(eid) || enc(pk_v) || enc(T_cred)) in Z_p."""
    return hash_to_scalar(TAG_ATTR, eid + pk + u256(t_cred))


def _poly_eval(coeffs, x):
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % R
    return acc


def keygen_dealer(n: int, t: int):
    """Trusted-dealer Shamir sharing (reference / fallback)."""
    fx = [rand_scalar() for _ in range(t)]
    fy = [rand_scalar() for _ in range(t)]
    return _finish_keys(n, [(_poly_eval(fx, i), _poly_eval(fy, i)) for i in range(1, n + 1)],
                        fx[0], fy[0])


def keygen_dkg(n: int, t: int):
    """Joint-Feldman (Pedersen) DKG for (x, y); GJKR [35] additionally makes the key uniform.

    Every issuer j deals two degree-(t-1) polynomials, publishes Feldman
    commitments in G2 (for x and y) and G1 (for y) and sends shares; every
    receiver verifies every share against the commitments.  Returns the
    same objects as keygen_dealer.  (Complaint rounds are not triggered in
    an honest run and are therefore not timed.)
    """
    deals = []
    for _ in range(n):
        fx = [rand_scalar() for _ in range(t)]
        fy = [rand_scalar() for _ in range(t)]
        Cx = [mul2(g2, a) for a in fx]
        Cy = [mul2(g2, a) for a in fy]
        Cy1 = [mul1(g1, a) for a in fy]
        deals.append((fx, fy, Cx, Cy, Cy1))
    shares = []
    for i in range(1, n + 1):
        xi = yi = 0
        powers = [pow(i, k, R) for k in range(t)]
        for fx, fy, Cx, Cy, Cy1 in deals:
            sx, sy = _poly_eval(fx, i), _poly_eval(fy, i)
            # Feldman verification of the received shares
            assert mul2(g2, sx) == msm2(Cx, powers)
            assert mul2(g2, sy) == msm2(Cy, powers)
            xi, yi = (xi + sx) % R, (yi + sy) % R
        shares.append((xi, yi))
    x = sum(d[0][0] for d in deals) % R
    y = sum(d[1][0] for d in deals) % R
    return _finish_keys(n, shares, x, y)


def _finish_keys(n, shares, x, y):
    keys = []
    mvk = MasterVK(alpha=mul2(g2, x), beta2=mul2(g2, y), beta1=mul1(g1, y))
    for i, (xi, yi) in enumerate(shares, start=1):
        k = IssuerKey(i, xi, yi, mul2(g2, xi), mul2(g2, yi), mul1(g1, yi))
        keys.append(k)
        mvk.vks[i] = (k.alpha, k.beta2, k.beta1)
    return keys, mvk


# --------------------------------------------------------------------------
# Issuance
# --------------------------------------------------------------------------
@dataclass
class IssueRequest:
    eid: bytes
    C: G1
    D: G1
    pi: tuple  # (c, z_m, z_o, z_r)

    def to_bytes(self) -> bytes:
        return self.eid + enc1(self.C) + enc1(self.D) + concat(encS(v) for v in self.pi)


@dataclass
class IssueState:
    m: int
    r: int
    h: G1


def H1(C: G1) -> G1:
    return G1.hash_to_curve(DST_H1, enc1(C))


def prepare_issue(eid: bytes, pk: bytes, t_cred: int):
    m = attr(eid, pk, t_cred)
    o, r = rand_scalar(), rand_scalar()
    C = msm1([g1, h1], [o, m])
    h = H1(C)
    D = msm1([g1, h], [r, m])
    # Schnorr PoK{(m,o,r): C = g1^o h1^m  and  D = g1^r h^m}
    wm, wo, wr = rand_scalar(), rand_scalar(), rand_scalar()
    T1 = msm1([g1, h1], [wo, wm])
    T2 = msm1([g1, h], [wr, wm])
    c = hash_to_scalar(TAG_ISS, eid + enc1(C) + enc1(D) + enc1(T1) + enc1(T2))
    pi = (c, (wm - c * m) % R, (wo - c * o) % R, (wr - c * r) % R)
    return IssueRequest(eid, C, D, pi), IssueState(m, r, h)


def verify_issue_request(req: IssueRequest) -> G1 | None:
    c, zm, zo, zr = req.pi
    h = H1(req.C)
    T1 = msm1([g1, h1, req.C], [zo, zm, c])
    T2 = msm1([g1, h, req.D], [zr, zm, c])
    ok = c == hash_to_scalar(TAG_ISS, req.eid + enc1(req.C) + enc1(req.D) + enc1(T1) + enc1(T2))
    return h if ok else None


def blind_issue(key: IssuerKey, req: IssueRequest):
    """Issuer side: verify pi_iss, then return (h, c_i = h^x_i D^y_i)."""
    h = verify_issue_request(req)
    if h is None:
        raise ValueError("invalid issuance proof")
    return h, msm1([h, req.D], [key.x, key.y])


def unblind(share, st: IssueState, index: int, mvk: MasterVK):
    """s_i = c_i beta1_i^{-r}; check e(h, alpha_i beta2_i^m) = e(s_i, g2)."""
    h, ci = share
    alpha_i, beta2_i, beta1_i = mvk.vks[index]
    si = ci + mul1(beta1_i, (-st.r) % R)
    lhs = alpha_i + mul2(beta2_i, st.m)
    if not pairing_check([h, -si], [lhs, g2]):
        raise ValueError("invalid credential share")
    return h, si


def aggregate(shares: dict, st: IssueState, mvk: MasterVK, verify: bool = True):
    """shares: index -> (h, s_i).  Returns sigma = (h, s)."""
    idx = sorted(shares)
    lag = lagrange_at_zero(idx)
    h = shares[idx[0]][0]
    s = msm1([shares[i][1] for i in idx], lag)
    if verify and not pairing_check([h, -s], [mvk.alpha + mul2(mvk.beta2, st.m), g2]):
        raise ValueError("aggregate credential does not verify")
    return h, s


# --------------------------------------------------------------------------
# Showing
# --------------------------------------------------------------------------
@dataclass
class Showing:
    hp: G1
    sp: G1

    def to_bytes(self) -> bytes:
        return enc1(self.hp) + enc1(self.sp)

    SIZE = 256


def prove(sigma, mvk: MasterVK, eid: bytes, pk: bytes, t_cred: int) -> Showing:
    """TIAC.Show: re-randomise the aggregate credential."""
    h, s = sigma
    rho = rand_scalar()
    return Showing(mul1(h, rho), mul1(s, rho))


def verify(mvk: MasterVK, eid: bytes, pk: bytes, t_cred: int, th: Showing) -> bool:
    """h' != 1 and e(h', alpha beta2^m) = e(s', g2), with m = H_attr(eid, pk, T_cred)."""
    if th.hp == ID1:
        return False
    m = attr(eid, pk, t_cred)
    return pairing_check([th.hp, -th.sp], [mvk.alpha + mul2(mvk.beta2, m), g2])
