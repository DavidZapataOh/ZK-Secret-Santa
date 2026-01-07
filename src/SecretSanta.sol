// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SecretSanta {
    enum EventStatus {
        ACTIVE,
        COMPLETED,
        CANCELLED
    }

    struct Event {
        uint256 id;
        uint256 maxParticipants;
        uint256 duration;
        bytes32 participantsSMTRoot;
        bytes32 signatureCommitmentSMTRoot;
        EventStatus status;
        address lead;
        address creator;
        uint256 createdAt;
    }

    uint256 public counter;
    uint256 public immutable LEVELS;

    mapping(uint256 => Event) public events;
    mapping(uint256 => mapping(bytes32 => bool)) public commitmentUsed;
    mapping(uint256 => mapping(bytes32 => bool)) public nullifierUsed;

    event EventCreated(
        uint256 indexed eventId,
        address indexed creator,
        uint256 maxParticipants,
        uint256 duration
    );

    error InvalidMaxParticipants(uint256 maxParticipants);
    error InvalidDuration(uint256 duration);

    constructor(uint256 _levels) {
        LEVELS = _levels;
    }

    function createEvent(
        uint256 _maxParticipants,
        uint256 _duration,
        address _lead
    ) external returns (uint256 eventId) {
        if (_maxParticipants == 0)
            revert InvalidMaxParticipants(_maxParticipants);
        if (_duration == 0) revert InvalidDuration(_duration);

        eventId = ++counter;

        Event storage e = events[eventId];

        e.id = eventId;
        e.maxParticipants = _maxParticipants;
        e.duration = _duration;
        e.participantsSMTRoot = bytes32(0); // TODO: implement SMT contract
        e.signatureCommitmentSMTRoot = bytes32(0); // TODO: implement SMT contract
        e.status = EventStatus.ACTIVE;
        e.lead = _lead;
        e.creator = msg.sender;
        e.createdAt = block.timestamp;

        emit EventCreated(eventId, msg.sender, _maxParticipants, _duration);
    }
}
