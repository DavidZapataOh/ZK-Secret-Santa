// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Register} from "./Register.sol";
import {SparseMerkleTree} from "@solarity/contracts/libs/data-structures/SparseMerkleTree.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IVerifier} from "./verifiers/IVerifier.sol";
import {Poseidon2, Field} from "@poseidon/src/Poseidon2.sol";

contract SecretSanta is Ownable {
    using SparseMerkleTree for SparseMerkleTree.Bytes32SMT;

    enum EventStatus {
        COMMIT,
        SENDERS_DETERMINED,
        RECEIVERS_DISCLOSED,
        COMPLETED
    }

    struct SenderEntry {
        bytes32 r; // RSA public key
        bytes32 nulls; // sender nullifier
    }

    Register public immutable register;
    Poseidon2 public immutable HASHER;
    IVerifier public immutable verifierSender;
    IVerifier public immutable verifierReceiver;

    uint32 public immutable commitmentsTreeDepth;
    uint256 public immutable eventNonce;
    bytes32 public immutable eventId;

    bytes32 public immutable participantsSMTRoot;
    SparseMerkleTree.Bytes32SMT internal _commitments;

    EventStatus public status;
    SenderEntry[] public giftSenders;

    mapping(address => bool) public commitmentUsed;
    mapping(address => bytes32) public commitmentOf;
    mapping(bytes32 => bool) public spentSenderNulls;
    mapping(bytes32 => bool) public chosenSenderNulls;
    mapping(bytes32 => uint256) public senderIndexPlus1ByNulls; // 1-based index
    mapping(address => bool) public receiverDisclosed;
    mapping(bytes32 => bytes) public encryptedPayloadByNulls;

    event EventCreated(
        uint256 indexed eventId,
        address indexed creator,
        uint256 maxParticipants,
        uint256 duration
    );
    event PhaseAdvanced(EventStatus status);
    event Commited(
        address indexed participant,
        bytes32 commitment,
        bytes32 root
    );
    event SenderDetermined(bytes32 r, bytes32 nullifier, uint256 index);
    event ReceiverDisclosed(
        address indexed receiver,
        bytes32 nullifier,
        bytes32 encryptedPayload
    );

    error InvalidMaxParticipants(uint256 maxParticipants);
    error InvalidEventStatus(EventStatus status);
    error InvalidProof();
    error InvalidPublicInputs();
    error InvalidEventId(bytes32 eventId);
    error InvalidParticipantsSMTRoot(bytes32 participantsSMTRoot);
    error InvalidSignatureCommitmentSMTRoot(bytes32 signatureCommitmentSMTRoot);
    error CommitmentAlreadyUsed();
    error NullifierAlreadyUsed();
    error SenderAlreadyDetermined();
    error ReceiverAlreadyDisclosed();
    error InvalidAddress();
    error RegistryNotFrozen();
    error ParticipantNotRegistered(address participant);
    error UnknownSenderNullifier();

    constructor(
        address _owner,
        Register _register,
        IVerifier _verifierSender,
        IVerifier _verifierReceiver,
        Poseidon2 _hasher,
        uint256 _eventNonce,
        uint32 _commitmentsTreeDepth
    ) Ownable(_owner) {
        register = _register;
        verifierSender = _verifierSender;
        verifierReceiver = _verifierReceiver;
        HASHER = _hasher;

        if (!register.frozen()) revert RegistryNotFrozen();

        eventNonce = _eventNonce;
        eventId = keccak256(abi.encodePacked(address(this), _eventNonce));
        participantsSMTRoot = _register.getRoot();

        _commitments.initialize(_commitmentsTreeDepth);
        _commitments.setHashers(_hash2, _hash3);

        commitmentsTreeDepth = _commitmentsTreeDepth;
        status = EventStatus.COMMIT;
    }

    function advancePhase() external onlyOwner {
        if (status == EventStatus.COMMIT) {
            status = EventStatus.SENDERS_DETERMINED;
        } else if (status == EventStatus.SENDERS_DETERMINED) {
            status = EventStatus.RECEIVERS_DISCLOSED;
        } else if (status == EventStatus.RECEIVERS_DISCLOSED) {
            status = EventStatus.COMPLETED;
        }
        emit PhaseAdvanced(status);
    }

    function commitSignature(bytes32 _H) external {
        if (status != EventStatus.COMMIT) revert InvalidEventStatus(status);
        if (!register.isRegistered(msg.sender)) revert InvalidAddress();
        if (commitmentUsed[msg.sender]) revert CommitmentAlreadyUsed();

        commitmentUsed[msg.sender] = true;
        commitmentOf[msg.sender] = _H;

        // check if msg.sender is in SMT
        bytes32 key = register.keyOf(msg.sender);
        SparseMerkleTree.Node memory n = register.getNodeByKey(key);
        if (n.nodeType != SparseMerkleTree.NodeType.LEAF) {
            revert ParticipantNotRegistered(msg.sender);
        }
        if (n.value != bytes32(uint256(uint160(msg.sender)))) {
            revert ParticipantNotRegistered(msg.sender);
        }

        // add signature commitment to SMT
        _commitments.add(_H, _H);

        emit Commited(msg.sender, _H, _commitments.getRoot());
    }

    function commitmentsRoot() external view returns (bytes32) {
        return _commitments.getRoot();
    }

    function getCommitmentProof(
        bytes32 _H
    ) external view returns (SparseMerkleTree.Proof memory) {
        return _commitments.getProof(_H);
    }

    function senderDetermination(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external {
        if (status != EventStatus.SENDERS_DETERMINED)
            revert InvalidEventStatus(status);

        if (_publicInputs.length != 6) revert InvalidPublicInputs();

        bytes32 r_ = _publicInputs[0];
        bytes32 eventId_ = _eventIdFromHiLo(_publicInputs[1], _publicInputs[2]);
        bytes32 rootP_ = _publicInputs[3];
        bytes32 rootC_ = _publicInputs[4];
        bytes32 nulls_ = _publicInputs[5];

        if (eventId_ != eventId) revert InvalidEventId(eventId_);
        if (rootP_ != participantsSMTRoot)
            revert InvalidParticipantsSMTRoot(rootP_);
        if (rootC_ != _commitments.getRoot())
            revert InvalidSignatureCommitmentSMTRoot(rootC_);
        if (spentSenderNulls[nulls_]) revert NullifierAlreadyUsed();

        spentSenderNulls[nulls_] = true;

        giftSenders.push(SenderEntry({r: r_, nulls: nulls_}));
        senderIndexPlus1ByNulls[nulls_] = giftSenders.length;

        if (!verifierSender.verify(_proof, _publicInputs)) {
            revert InvalidProof();
        }

        emit SenderDetermined(r_, nulls_, giftSenders.length - 1);
    }

    function sendersCount() external view returns (uint256) {
        return giftSenders.length;
    }

    function receiverDisclosure(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs,
        bytes calldata encryptedPayload
    ) external {
        if (status != EventStatus.RECEIVERS_DISCLOSED)
            revert InvalidEventStatus(status);

        if (!register.isRegistered(msg.sender))
            revert ParticipantNotRegistered(msg.sender);

        if (receiverDisclosed[msg.sender]) revert ReceiverAlreadyDisclosed();

        if (_publicInputs.length != 4) revert InvalidPublicInputs();

        uint256 a = uint256(_publicInputs[0]);
        if (a >> 160 != 0) revert InvalidAddress();
        address receiver_ = address(uint160(a));
        bytes32 eventId_ = _eventIdFromHiLo(_publicInputs[1], _publicInputs[2]);
        bytes32 nulls_ = _publicInputs[3];

        if (eventId_ != eventId) revert InvalidEventId(eventId_);
        if (chosenSenderNulls[nulls_]) revert NullifierAlreadyUsed();
        if (receiver_ != msg.sender) revert InvalidAddress();

        // check if receiver is in SMT
        bytes32 key = register.keyOf(receiver_);
        SparseMerkleTree.Node memory n = register.getNodeByKey(key);
        if (n.nodeType != SparseMerkleTree.NodeType.LEAF) {
            revert ParticipantNotRegistered(receiver_);
        }
        if (n.value != bytes32(uint256(uint160(receiver_)))) {
            revert ParticipantNotRegistered(receiver_);
        }

        uint256 idxPlus1 = senderIndexPlus1ByNulls[nulls_];
        if (idxPlus1 == 0) revert UnknownSenderNullifier();

        if (!verifierReceiver.verify(_proof, _publicInputs)) {
            revert InvalidProof();
        }

        chosenSenderNulls[nulls_] = true;
        receiverDisclosed[msg.sender] = true;
        encryptedPayloadByNulls[nulls_] = encryptedPayload;

        emit ReceiverDisclosed(receiver_, nulls_, keccak256(encryptedPayload));
    }

    function getPayloadForSender(
        bytes32 myNulls
    ) external view returns (bytes memory) {
        return encryptedPayloadByNulls[myNulls];
    }

    function _eventIdFromHiLo(
        bytes32 hi,
        bytes32 lo
    ) internal pure returns (bytes32) {
        uint256 hiU = uint256(hi);
        uint256 loU = uint256(lo);
        // each limb must fit in 128 bits
        if (hiU >> 128 != 0) revert InvalidPublicInputs();
        if (loU >> 128 != 0) revert InvalidPublicInputs();
        return bytes32((hiU << 128) | loU);
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
