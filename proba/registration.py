"""
Algorithm 6 (v3.4): blind, threshold wallet authorization with independent
authentication by every issuer.

* RegDB[eid, ID] in {unused, pending, issued} is kept by the registration
  service, which reserves a request atomically (unused -> pending) and signs a
  one-use token bound to (eid, rid, H(req), H(ID)).
* Every issuer authenticates the civil identity ITSELF (here: an Ed25519
  challenge-response against the identity's authentication key, which the
  issuer obtained through its own enrolment channel).  A malicious registration
  service therefore cannot obtain shares for an identity it cannot
  authenticate as -- in particular not for abstaining voters.
* Every honest issuer keeps a local record and returns at most one share per
  identity and election; returned shares are counted in the shared state.
* A pending registration may be released (-> unused) only if NO share has been
  returned for it: otherwise already returned honest shares could later be
  completed by corrupted issuers into a second credential.
* Civil-identity authentication is represented by the challenge-response only;
  a real deployment substitutes its eID / SSO mechanism.
"""
from __future__ import annotations

import os
import threading
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .crypto import keccak256, sha256, u256
from . import tiac as TIAC


class Identity:
    """A civil identity with its authentication credential (e.g. an eID key)."""

    def __init__(self, ID: str):
        self.ID = ID
        self._sk = Ed25519PrivateKey.generate()
        self.auth_pk = self._sk.public_key()

    def respond(self, eid: bytes, issuer: int, nonce: bytes, hreq: bytes) -> bytes:
        return self._sk.sign(eid + u256(issuer) + nonce + hreq)


def hid(ID: str) -> bytes:
    return keccak256(ID.encode())


class RegistrationService:
    def __init__(self, eid: bytes, eligible: set, t_open: int, t_close: int, t_i: int):
        self.eid = eid
        self.eligible = set(eligible)
        self.t_open, self.t_close, self.t_i = t_open, t_close, t_i
        self.state = {}                 # ID -> unused | pending | issued
        self.req_of = {}                # rid -> ID
        self.shares = {}                # rid -> set of issuer indices that returned a share
        self.receipts = []
        self._lock = threading.Lock()
        self._sk = Ed25519PrivateKey.generate()
        self.token_pk = self._sk.public_key()

    def authorize(self, ID: str, req: TIAC.IssueRequest, now: int):
        """Step 2: window, eligibility, atomic unused -> pending, token."""
        if not (self.t_open <= now <= self.t_close):
            raise PermissionError("outside registration window")
        if ID not in self.eligible:
            raise PermissionError("ineligible identity")
        with self._lock:
            if self.state.get(ID, "unused") != "unused":
                raise PermissionError("identity already used")
            self.state[ID] = "pending"
            rid = os.urandom(16)
            self.req_of[rid] = ID
            self.shares[rid] = set()
        hreq = keccak256(req.to_bytes())
        return rid, hreq, self._sk.sign(self.eid + rid + hreq + hid(ID))

    def is_pending(self, rid: bytes) -> bool:
        return self.state.get(self.req_of.get(rid)) == "pending"

    def record_share(self, rid: bytes, issuer: int):
        with self._lock:
            self.shares[rid].add(issuer)

    def complete(self, rid: bytes):
        """Step 5: pending -> issued once t_i shares were returned; publish a
        receipt that names neither the wallet nor the request."""
        with self._lock:
            ID = self.req_of[rid]
            if self.state[ID] != "pending" or len(self.shares[rid]) < self.t_i:
                raise PermissionError("threshold not reached")
            self.state[ID] = "issued"
            self.receipts.append(sha256(self.eid + ID.encode() + b"issued"))

    def release(self, rid: bytes):
        """Auditable timeout: allowed only if no share has been returned."""
        with self._lock:
            ID = self.req_of[rid]
            if self.state[ID] != "pending" or self.shares[rid]:
                raise PermissionError("cannot release: shares already returned")
            self.state[ID] = "unused"
            del self.req_of[rid]


class Issuer:
    def __init__(self, key: TIAC.IssuerKey, reg: RegistrationService, enrolment: dict):
        self.key, self.reg = key, reg
        self.enrolment = dict(enrolment)   # ID -> authentication public key (own channel)
        self.issued_ids = set()            # local one-share-per-identity record
        self.seen_rids = set()
        self._nonces = {}

    def challenge(self, ID: str) -> bytes:
        n = os.urandom(32)
        self._nonces[ID] = n
        return n

    def issue(self, req: TIAC.IssueRequest, rid: bytes, hreq: bytes, token: bytes,
              ID: str, response: bytes):
        """Step 3: authenticate ID independently, check token/state/record, BlindIssue."""
        nonce = self._nonces.pop(ID, None)
        if nonce is None or ID not in self.enrolment:
            raise PermissionError("unknown identity or no challenge")
        self.enrolment[ID].verify(response, self.reg.eid + u256(self.key.index) + nonce + hreq)
        self.reg.token_pk.verify(token, self.reg.eid + rid + hreq + hid(ID))
        if keccak256(req.to_bytes()) != hreq:
            raise PermissionError("token not bound to this request")
        if ID in self.issued_ids:
            raise PermissionError("share already issued to this identity")
        if rid in self.seen_rids or not self.reg.is_pending(rid) or self.reg.req_of.get(rid) != ID:
            raise PermissionError("replayed, non-pending or mismatching request")
        share = TIAC.blind_issue(self.key, req)
        self.issued_ids.add(ID)
        self.seen_rids.add(rid)
        self.reg.record_share(rid, self.key.index)
        return share


def setup_registration(eid, identities, keys, t_i, t_open=0, t_close=2 ** 41):
    """Registration service + issuers, each with its own enrolment copy."""
    reg = RegistrationService(eid, {v.ID for v in identities}, t_open, t_close, t_i)
    enrol = {v.ID: v.auth_pk for v in identities}
    return reg, [Issuer(k, reg, enrol) for k in keys]


def register_voter(ident: Identity, wallet, eid, t_cred, reg, issuers, mvk, t_i, now, timings=None):
    """Voter side of Algorithm 6 with t_i issuers (executed sequentially)."""
    tm = timings if timings is not None else {}
    t0 = time.perf_counter()
    req, st = TIAC.prepare_issue(eid, wallet.pk, t_cred)
    t1 = time.perf_counter()
    rid, hreq, token = reg.authorize(ident.ID, req, now)
    t2 = time.perf_counter()
    shares = {}
    tauth = tiss = tunb = 0.0
    for iss in issuers[:t_i]:
        a = time.perf_counter()
        nonce = iss.challenge(ident.ID)
        resp = ident.respond(eid, iss.key.index, nonce, hreq)
        b = time.perf_counter()
        sh = iss.issue(req, rid, hreq, token, ident.ID, resp)
        c = time.perf_counter()
        shares[iss.key.index] = TIAC.unblind(sh, st, iss.key.index, mvk)
        d = time.perf_counter()
        tauth += b - a; tiss += c - b; tunb += d - c
    t3 = time.perf_counter()
    sigma = TIAC.aggregate(shares, st, mvk)
    t4 = time.perf_counter()
    reg.complete(rid)
    t5 = time.perf_counter()
    tm.update(prep=t1 - t0, authorize=t2 - t1, auth_voter=tauth, issue_total=tiss, unblind_total=tunb,
              aggregate=t4 - t3, complete=t5 - t4, total=t5 - t0)
    return sigma
