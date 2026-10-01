// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title PROBA v3.4 bulletin-board contract
/// @notice Implements the public acceptance predicate of Algorithm 7
///         (checks C1-C5) and Latest[pk] = (seq, cid, tau, t_last).
///         BLS12-381 operations use the EIP-2537 precompiles (Prague).
///         Byte layout of the ballot object B_v (EIP-2537 wire encoding):
///           0   eid        32
///           32  pk_v       64   (secp256k1, uncompressed x||y)
///           96  T_cred     32
///           128 seq_v      32
///           160 n_c        32
///           192 ct_v       256*n_c        (A_j || B_j, G1 points)
///           ..  pi_bal     128*n_c + 64   ((c0,c1,z0,z1)_j , (c,z))
///           ..  Theta_v    256            (h', s')
contract ProbaElection {
    // ---------------------------------------------------------------- constants
    uint256 internal constant R =
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;
    uint256 internal constant R2_256 =
        0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe;
    uint256 internal constant HALF_N =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    bytes32 internal constant TAG_SIG = keccak256("PROBA-v3.4");
    bytes32 internal constant TAG_ATTR = keccak256("PROBA-v3.4/attr");
    bytes32 internal constant TAG_BAL01 = keccak256("PROBA-v3.4/fs/ballot01");
    bytes32 internal constant TAG_BALSUM = keccak256("PROBA-v3.4/fs/ballotsum");

    address internal constant G1ADD = address(0x0b);
    address internal constant G1MSM = address(0x0c);
    address internal constant G2ADD = address(0x0d);
    address internal constant G2MSM = address(0x0e);
    address internal constant PAIRING = address(0x0f);

    // Params blob (SSTORE2): gE | mpk | -g2 | alpha | beta2
    uint256 internal constant P_GE = 0;
    uint256 internal constant P_Y = 128;
    uint256 internal constant P_NG2 = 256;
    uint256 internal constant P_ALPHA = 512;
    uint256 internal constant P_BETA2 = 768;
    uint256 internal constant P_LEN = 1024;

    // ---------------------------------------------------------------- Params
    bytes32 public immutable EID;
    uint256 public immutable NC;
    uint256 public immutable TI;
    uint256 public immutable TD;
    uint256 public immutable T_REG_OPEN;
    uint256 public immutable T_REG_CLOSE;
    uint256 public immutable T_VOTE_OPEN;
    uint256 public immutable T_VOTE_CLOSE;
    uint256 public immutable T_CRED;
    uint256 public immutable S_MAX;        // cap on seq (accepted ballots per wallet)
    uint256 public immutable DELTA_MIN;    // minimum spacing of two accepted ballots of a wallet
    address public immutable PARAMS;

    // ---------------------------------------------------------------- state
    struct Rec {
        uint64 seq;
        uint8 v;
        uint64 tLast;      // packed with seq and v into one slot
        bytes32 cid;
        bytes32 r;
        bytes32 s;
    }
    mapping(bytes32 => Rec) public latest;   // key = keccak256(pk_v)

    event BallotAccepted(bytes32 indexed pkHash, uint64 seq, bytes32 cid, uint8 v, bytes32 r, bytes32 s);
    event GasProfile(uint256 c1, uint256 c2, uint256 c3, uint256 c4, uint256 c5store);

    constructor(
        bytes32 eid,
        uint256 nc,
        uint256[9] memory cfg,   // ti, td, regOpen, regClose, voteOpen, voteClose, tCred, sMax, deltaMin
        bytes memory paramBlob
    ) {
        require(paramBlob.length == P_LEN, "params");
        EID = eid;
        NC = nc;
        TI = cfg[0];
        TD = cfg[1];
        T_REG_OPEN = cfg[2];
        T_REG_CLOSE = cfg[3];
        T_VOTE_OPEN = cfg[4];
        T_VOTE_CLOSE = cfg[5];
        T_CRED = cfg[6];
        require(cfg[7] >= 1 && cfg[7] < 2 ** 64, "sMax");
        S_MAX = cfg[7];
        DELTA_MIN = cfg[8];
        // SSTORE2: deploy params as the code of a data contract.
        bytes memory code = abi.encodePacked(hex"00", paramBlob);
        bytes memory init = abi.encodePacked(hex"63", uint32(code.length), hex"80600e6000396000f3", code);
        address ptr;
        assembly {
            ptr := create(0, add(init, 32), mload(init))
        }
        require(ptr != address(0), "sstore2");
        PARAMS = ptr;
    }

    function params() external view returns (bytes memory) {
        return _code(0, P_LEN);
    }

    // ---------------------------------------------------------------- casting
    function cast(bytes calldata B, bytes32 cid, uint8 v, bytes32 r, bytes32 s) external {
        _cast(B, cid, v, r, s, false);
    }

    /// Identical to cast() but additionally emits the gas consumed by each check.
    function castProfiled(bytes calldata B, bytes32 cid, uint8 v, bytes32 r, bytes32 s) external {
        _cast(B, cid, v, r, s, true);
    }

    function _cast(bytes calldata B, bytes32 cid, uint8 v, bytes32 r, bytes32 s, bool prof) internal {
        uint256[5] memory g;
        g[0] = gasleft();
        // ---- C1: layout, context, time window, credential expiry, content identifier
        uint256 n = NC;
        require(B.length == 512 + 384 * n, "C1:len");
        require(bytes32(B[0:32]) == EID, "C1:eid");
        require(uint256(bytes32(B[160:192])) == n, "C1:nc");
        uint256 tCred = uint256(bytes32(B[96:128]));
        require(tCred == T_CRED, "C1:tcred");
        require(block.timestamp >= T_VOTE_OPEN && block.timestamp <= T_VOTE_CLOSE && block.timestamp <= tCred, "C1:time");
        require(sha256(B) == cid, "C1:cid");
        g[1] = gasleft();

        // ---- C2: wallet signature on M_v = (PROBA-v3.4, eid, pk, seq, cid)
        bytes calldata pk = B[32:96];
        uint256 seq = uint256(bytes32(B[128:160]));
        {
            bytes32 md = keccak256(abi.encodePacked(TAG_SIG, EID, pk, seq, cid));
            bytes32 ed = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", md));
            require(uint256(s) <= HALF_N, "C2:s");
            address a = address(uint160(uint256(keccak256(pk))));
            require(ecrecover(ed, v, r, s) == a && a != address(0), "C2:sig");
        }
        g[2] = gasleft();

        // ---- C3: re-randomised credential Theta_v = (h', s') on m_v = H_attr(eid, pk, T_cred)
        require(_verifyShow(B, pk, tCred, n), "C3:cred");
        g[3] = gasleft();

        // ---- C4: ballot validity and one-selection proofs
        require(_verifyBallot(B, pk, seq, n), "C4:ballot");
        g[4] = gasleft();

        // ---- C5: latest-valid-ballot rule with per-wallet rate limit, then state update
        bytes32 key = keccak256(pk);
        Rec storage rec = latest[key];
        require(seq > rec.seq && seq <= S_MAX, "C5:seq");
        require(rec.seq == 0 || block.timestamp >= uint256(rec.tLast) + DELTA_MIN, "C5:interval");
        rec.seq = uint64(seq);
        rec.v = v;
        rec.tLast = uint64(block.timestamp);
        rec.cid = cid;
        rec.r = r;
        rec.s = s;
        emit BallotAccepted(key, uint64(seq), cid, v, r, s);
        if (prof) {
            emit GasProfile(g[0] - g[1], g[1] - g[2], g[2] - g[3], g[3] - g[4], g[4] - gasleft());
        }
    }

    // ---------------------------------------------------------------- C3
    /// h' != 1 and e(h', alpha * beta2^m) * e(s', -g2) == 1.  Both points enter
    /// the pairing precompile, which performs the subgroup checks.
    function _verifyShow(bytes calldata B, bytes calldata pk, uint256 tCred, uint256 n)
        internal view returns (bool)
    {
        uint256 o = 256 + 384 * n;                    // start of Theta_v == |A_v|
        bytes memory hp = B[o:o + 128];
        if (_isZero(hp)) return false;
        uint256 m = _hs(TAG_ATTR, abi.encodePacked(EID, pk, tCred));
        bytes memory bm = _pc(G2MSM, abi.encodePacked(_code(P_BETA2, 256), m), 256);
        bytes memory K = _pc(G2ADD, abi.encodePacked(_code(P_ALPHA, 256), bm), 256);
        bytes memory out = _pc(PAIRING, abi.encodePacked(hp, K, B[o + 128:o + 256], _code(P_NG2, 256)), 32);
        return uint256(bytes32(out)) == 1;
    }

    // ---------------------------------------------------------------- C4
    function _verifyBallot(bytes calldata B, bytes calldata pk, uint256 seq, uint256 n)
        internal view returns (bool)
    {
        bytes memory gE = _code(P_GE, 128);
        bytes memory Y = _code(P_Y, 128);
        bytes memory prefix = abi.encodePacked(EID, pk, seq, keccak256(B[192:192 + 256 * n]));
        bytes memory SA = new bytes(128);
        bytes memory SB = new bytes(128);
        uint256 pfo = 192 + 256 * n;
        for (uint256 j = 0; j < n; j++) {
            uint256 co = 192 + 256 * j;
            uint256 po = pfo + 128 * j;
            if (!_verify01(prefix, j, gE, Y, B[co:co + 128], B[co + 128:co + 256], B[po:po + 128])) return false;
            _addInto(SA, B[co:co + 128]);
            _addInto(SB, B[co + 128:co + 256]);
        }
        uint256 so = pfo + 128 * n;
        uint256 c = uint256(bytes32(B[so:so + 32]));
        uint256 z = uint256(bytes32(B[so + 32:so + 64]));
        if (c >= R || z >= R) return false;
        bytes memory a = _pc(G1MSM, abi.encodePacked(gE, z, SA, R - c), 128);
        bytes memory b = _pc(G1MSM, abi.encodePacked(Y, z, SB, R - c, gE, c), 128);
        return c == _hs(TAG_BALSUM, abi.encodePacked(prefix, SA, SB, a, b));
    }

    function _verify01(
        bytes memory prefix, uint256 j, bytes memory gE, bytes memory Y,
        bytes calldata A, bytes calldata Bj, bytes calldata p
    ) internal view returns (bool) {
        uint256 c0 = uint256(bytes32(p[0:32]));
        uint256 c1 = uint256(bytes32(p[32:64]));
        uint256 z0 = uint256(bytes32(p[64:96]));
        uint256 z1 = uint256(bytes32(p[96:128]));
        if (c0 >= R || c1 >= R || z0 >= R || z1 >= R) return false;
        bytes memory a0 = _pc(G1MSM, abi.encodePacked(gE, z0, A, R - c0), 128);
        bytes memory b0 = _pc(G1MSM, abi.encodePacked(Y, z0, Bj, R - c0), 128);
        bytes memory a1 = _pc(G1MSM, abi.encodePacked(gE, z1, A, R - c1), 128);
        bytes memory b1 = _pc(G1MSM, abi.encodePacked(Y, z1, Bj, R - c1, gE, c1), 128);
        return addmod(c0, c1, R) == _hs(TAG_BAL01, abi.encodePacked(prefix, j, A, Bj, a0, b0, a1, b1));
    }

    // ---------------------------------------------------------------- helpers
    function _hs(bytes32 t, bytes memory data) internal pure returns (uint256) {
        bytes32 d = keccak256(abi.encodePacked(t, data));
        uint256 hi = uint256(keccak256(abi.encodePacked(d, uint8(0))));
        uint256 lo = uint256(keccak256(abi.encodePacked(d, uint8(1))));
        return addmod(mulmod(hi, R2_256, R), lo % R, R);
    }

    function _pc(address p, bytes memory input, uint256 outLen) internal view returns (bytes memory out) {
        out = new bytes(outLen);
        bool ok;
        assembly ("memory-safe") {
            ok := staticcall(gas(), p, add(input, 32), mload(input), add(out, 32), outLen)
        }
        require(ok, "precompile");
    }

    /// dst <- dst + x  (G1ADD; the all-zero encoding is the identity)
    function _addInto(bytes memory dst, bytes calldata x) internal view {
        bytes memory input = abi.encodePacked(dst, x);
        bool ok;
        assembly ("memory-safe") {
            ok := staticcall(gas(), 0x0b, add(input, 32), 256, add(dst, 32), 128)
        }
        require(ok, "g1add");
    }

    function _code(uint256 off, uint256 len) internal view returns (bytes memory out) {
        out = new bytes(len);
        address p = PARAMS;
        assembly ("memory-safe") {
            extcodecopy(p, add(out, 32), add(off, 1), len)
        }
    }

    function _isZero(bytes memory x) internal pure returns (bool) {
        for (uint256 i = 0; i < x.length; i += 32) {
            bytes32 w;
            assembly ("memory-safe") {
                w := mload(add(add(x, 32), i))
            }
            if (w != bytes32(0)) return false;
        }
        return true;
    }
}
