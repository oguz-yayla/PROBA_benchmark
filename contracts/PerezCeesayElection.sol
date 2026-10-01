// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title Perez--Ceesay blockchain-powered Helios baseline (Algorithm 4)
/// @notice The contract owner writes eligible wallet addresses on-chain
///         (step 1); a cast records the IPFS content identifier and the
///         wallet signature tau = Sign(sk, eid || cid) (steps 4-5).  Ballot
///         proofs are verified off-chain at tally time (step 6).
contract PerezCeesayElection {
    address public immutable owner;
    bytes32 public immutable EID;
    mapping(address => bool) public eligible;
    mapping(address => bytes32) public cidOf;

    event Authorized(address indexed wallet);
    event BallotRecorded(address indexed wallet, bytes32 cid, bytes tau);

    constructor(bytes32 eid) {
        owner = msg.sender;
        EID = eid;
    }

    function authorize(address[] calldata wallets) external {
        require(msg.sender == owner, "owner");
        for (uint256 i = 0; i < wallets.length; i++) {
            eligible[wallets[i]] = true;
            emit Authorized(wallets[i]);
        }
    }

    function cast(bytes32 cid, bytes calldata tau) external {
        require(eligible[msg.sender], "not eligible");
        cidOf[msg.sender] = cid;
        emit BallotRecorded(msg.sender, cid, tau);
    }
}
