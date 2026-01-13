// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {SparseMerkleTree} from "@solarity/contracts/libs/data-structures/SparseMerkleTree.sol";
import {Poseidon2, Field} from "@poseidon/src/Poseidon2.sol";

contract Register is Ownable {
    using SparseMerkleTree for SparseMerkleTree.Bytes32SMT;
    SparseMerkleTree.Bytes32SMT internal bytes32Tree;

    Poseidon2 public immutable HASHER;
    uint32 public immutable TREE_DEPTH;
    bool public frozen;

    mapping(address => bool) public isRegistered;

    error InvalidTreeDepth(uint32 treeDepth);
    error InvalidAddress();
    error TreeIsFrozen();
    error TreeNotFrozen();
    error ParticipantAlreadyRegistered(address participant);
    error ParticipantNotRegistered(address participant);

    event ParticipantRegistered(address indexed participant);
    event ParticipantUnregistered(address indexed participant);
    event TreeFrozen();
    event TreeUnfrozen();

    constructor(
        address _owner,
        Poseidon2 _hasher,
        uint32 _treeDepth
    ) Ownable(_owner) {
        if (_treeDepth == 0 || _treeDepth > 20)
            revert InvalidTreeDepth(_treeDepth);
        if (address(_hasher) == address(0)) revert InvalidAddress();
        TREE_DEPTH = _treeDepth;
        HASHER = _hasher;

        bytes32Tree.initialize(_treeDepth);
        bytes32Tree.setHashers(_hash2, _hash3);
    }

    function register(address _participant) external {
        if (frozen) revert TreeIsFrozen();
        if (isRegistered[_participant])
            revert ParticipantAlreadyRegistered(_participant);

        isRegistered[_participant] = true;

        bytes32 key = _keyOf(_participant);
        bytes32Tree.add(key, bytes32(uint256(1)));

        emit ParticipantRegistered(_participant);
    }

    function registerBatch(address[] calldata _participants) external {
        if (frozen) revert TreeIsFrozen();
        for (uint256 i = 0; i < _participants.length; i++) {
            address p = _participants[i];
            if (isRegistered[p]) revert ParticipantAlreadyRegistered(p);
            isRegistered[p] = true;
            bytes32 key = _keyOf(p);
            bytes32Tree.add(key, bytes32(uint256(1)));
            emit ParticipantRegistered(p);
        }
    }

    function freeze() external onlyOwner {
        if (frozen) revert TreeIsFrozen();
        frozen = true;
        emit TreeFrozen();
    }

    function unfreeze() external onlyOwner {
        if (!frozen) revert TreeNotFrozen();
        frozen = false;
        emit TreeUnfrozen();
    }

    function getProof(
        bytes32 _key
    ) external view virtual returns (SparseMerkleTree.Proof memory) {
        return bytes32Tree.getProof(_key);
    }

    function getRoot() external view virtual returns (bytes32) {
        return bytes32Tree.getRoot();
    }

    function keyOf(address participant) external view returns (bytes32) {
        return _keyOf(participant);
    }

    function getNodeByKey(
        bytes32 _key
    ) external view virtual returns (SparseMerkleTree.Node memory) {
        return bytes32Tree.getNodeByKey(_key);
    }

    function _keyOf(address _participant) internal view returns (bytes32) {
        return Field.toBytes32(HASHER.hash_1(Field.toField(_participant)));
    }

    function _hash2(bytes32 _x, bytes32 _y) internal view returns (bytes32) {
        return
            Field.toBytes32(
                HASHER.hash_2(Field.toField(_x), Field.toField(_y))
            );
    }

    function _hash3(
        bytes32 _x,
        bytes32 _y,
        bytes32 _z
    ) internal view returns (bytes32) {
        return
            Field.toBytes32(
                HASHER.hash_3(
                    Field.toField(_x),
                    Field.toField(_y),
                    Field.toField(_z)
                )
            );
    }
}
