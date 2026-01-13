// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Register} from "./Register.sol";
import {IVerifier} from "./verifiers/IVerifier.sol";
import {SecretSanta} from "./SecretSanta.sol";
import {Poseidon2} from "@poseidon/src/Poseidon2.sol";

contract SantaFactory is Ownable {
    Register public register;
    IVerifier public verifierSender;
    IVerifier public verifierReceiver;
    Poseidon2 public hasher;

    uint256 public nextEventNonce;

    mapping(bytes32 => address) public eventById;
    address[] public allEvents;

    event EventCreated(
        address indexed creator,
        bytes32 indexed eventId,
        address indexed eventContract,
        uint256 nonce
    );

    error RegistryNotFrozen();

    constructor(
        address _owner,
        Register _register,
        IVerifier _verifierSender,
        IVerifier _verifierReceiver,
        Poseidon2 _hasher
    ) Ownable(_owner) {
        register = _register;
        verifierSender = _verifierSender;
        verifierReceiver = _verifierReceiver;
        hasher = _hasher;
    }

    function createEvent(
        uint32 _commitmentsTreeDepth
    ) external returns (address eventAddr, bytes32 eventId) {
        if (!register.frozen()) revert RegistryNotFrozen();

        uint256 nonce = nextEventNonce++;

        SecretSanta ev = new SecretSanta(
            msg.sender,
            register,
            verifierSender,
            verifierReceiver,
            hasher,
            nonce,
            _commitmentsTreeDepth
        );

        eventAddr = address(ev);
        eventId = ev.eventId();

        eventById[eventId] = eventAddr;
        allEvents.push(eventAddr);

        emit EventCreated(msg.sender, eventId, eventAddr, nonce);
    }

    function eventsCount() external view returns (uint256) {
        return allEvents.length;
    }
}
