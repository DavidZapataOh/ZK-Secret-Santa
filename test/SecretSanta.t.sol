// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";

import {Poseidon2} from "@poseidon/src/Poseidon2.sol";
import {Register} from "../src/Register.sol";
import {SantaFactory} from "../src/SantaFactory.sol";
import {SecretSanta} from "../src/SecretSanta.sol";
import {IVerifier} from "../src/verifiers/IVerifier.sol";

import {HonkVerifier as SenderVerifier} from "../src/verifiers/SenderVerifier.sol";
import {HonkVerifier as ReceiverVerifier} from "../src/verifiers/ReceiverVerifier.sol";

contract SecretSantaTest is Test {
    uint32 internal constant DEPTH = 20;

    Poseidon2 internal hasher;
    Register internal reg;
    SantaFactory internal factory;

    SenderVerifier internal vSender;
    ReceiverVerifier internal vReceiver;

    address internal owner = makeAddr("owner");
    address internal creator = makeAddr("creator");
    address internal lead = makeAddr("lead");

    uint256 internal pkA = 0xA11CE;
    uint256 internal pkB = 0xB0B;
    uint256 internal pkC = 0xCAFE;

    address internal A;
    address internal B;
    address internal C;

    // cache to reduce stack pressure
    bytes32 internal EVENT_ID;
    bytes32 internal ROOT_P;
    bytes32 internal ROOT_C;

    function setUp() public {
        A = vm.addr(pkA);
        B = vm.addr(pkB);
        C = vm.addr(pkC);

        hasher = new Poseidon2();
        reg = new Register(owner, hasher, DEPTH);

        vSender = new SenderVerifier();
        vReceiver = new ReceiverVerifier();

        factory = new SantaFactory(
            owner,
            reg,
            IVerifier(address(vSender)),
            IVerifier(address(vReceiver)),
            hasher
        );

        vm.prank(owner);
        reg.setFactory(address(factory));

        reg.register(A);
        reg.register(B);
        reg.register(C);

        vm.prank(owner);
        reg.freeze();
    }

    function test_SecretSanta_FullFlow_3Participants() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);

        EVENT_ID = ev.eventId();

        (bytes32 HA, bytes32 nullA) = _commit(ev, pkA, A);
        (bytes32 HB, bytes32 nullB) = _commit(ev, pkB, B);
        (bytes32 HC, bytes32 nullC) = _commit(ev, pkC, C);

        vm.prank(creator);
        ev.advancePhase();

        ROOT_P = ev.participantsSMTRoot();
        ROOT_C = ev.commitmentsRoot();

        _determineSender(ev, pkA, A, HA);
        _determineSender(ev, pkB, B, HB);
        _determineSender(ev, pkC, C, HC);

        vm.prank(creator);
        ev.advancePhase();

        bytes memory payloadForB = abi.encodePacked(bytes32(uint256(111)));
        bytes memory payloadForC = abi.encodePacked(bytes32(uint256(222)));
        bytes memory payloadForA = abi.encodePacked(bytes32(uint256(333)));

        _disclose(ev, pkA, A, nullB, payloadForB);
        _disclose(ev, pkB, B, nullC, payloadForC);
        _disclose(ev, pkC, C, nullA, payloadForA);

        assertEq(
            keccak256(ev.getPayloadForSender(nullA)),
            keccak256(payloadForA)
        );
        assertEq(
            keccak256(ev.getPayloadForSender(nullB)),
            keccak256(payloadForB)
        );
        assertEq(
            keccak256(ev.getPayloadForSender(nullC)),
            keccak256(payloadForC)
        );
    }

    function _createEvent() internal returns (address evAddr, bytes32 eventId) {
        vm.prank(creator);
        (evAddr, eventId) = factory.createEvent(DEPTH, lead);
    }

    function _commit(
        SecretSanta ev,
        uint256 pk,
        address who
    ) internal returns (bytes32 H, bytes32 nullS) {
        (H, nullS) = _getCommitmentAndNulls(pk, who, EVENT_ID);
        vm.prank(who);
        ev.commitSignature(H);
    }

    function _determineSender(
        SecretSanta ev,
        uint256 pk,
        address who,
        bytes32 H
    ) internal {
        bytes32 keyP = reg.keyOf(who);

        bytes32[] memory sibPdyn = reg.getProof(keyP).siblings;
        bytes32[] memory sibCdyn = ev.getCommitmentProof(H).siblings;

        (bytes32[DEPTH] memory sibP, uint32 depthP) = _proofToFixed(sibPdyn);
        (bytes32[DEPTH] memory sibC, uint32 depthC) = _proofToFixed(sibCdyn);

        (bytes memory proof, bytes32[] memory pub) = _getSenderProof(
            pk,
            who,
            sibP,
            depthP,
            sibC,
            depthC
        );

        ev.senderDetermination(proof, pub);
    }

    function _disclose(
        SecretSanta ev,
        uint256 pk,
        address who,
        bytes32 senderNulls,
        bytes memory payload
    ) internal {
        (bytes memory proof, bytes32[] memory pub) = _getReceiverProof(
            pk,
            who,
            senderNulls
        );

        vm.prank(who);
        ev.receiverDisclosure(proof, pub, payload);
    }

    function _getCommitmentAndNulls(
        uint256 pk,
        address who,
        bytes32 eventId
    ) internal returns (bytes32 H, bytes32 nullS) {
        uint256 NUM_ARGS = 6;
        string[] memory args = new string[](NUM_ARGS);

        args[0] = "npx";
        args[1] = "tsx";
        args[2] = "js-scripts/getCommitmentAndNulls.ts";
        args[3] = vm.toString(pk);
        args[4] = vm.toString(who);
        args[5] = vm.toString(eventId);

        bytes memory out = vm.ffi(args);
        (H, nullS) = abi.decode(out, (bytes32, bytes32));
    }

    function _getSenderProof(
        uint256 pk,
        address who,
        bytes32[DEPTH] memory sibP,
        uint32 depthP,
        bytes32[DEPTH] memory sibC,
        uint32 depthC
    ) internal returns (bytes memory proof, bytes32[] memory publicInputs) {
        string[] memory args = new string[](3 + 6 + DEPTH + 1 + DEPTH + 1);
        uint256 k;

        args[k++] = "npx";
        args[k++] = "tsx";
        args[k++] = "js-scripts/generateProofSender.ts";

        args[k++] = vm.toString(pk);
        args[k++] = vm.toString(who);
        args[k++] = vm.toString(EVENT_ID);
        args[k++] = vm.toString(ROOT_P);
        args[k++] = vm.toString(ROOT_C);

        args[k++] = vm.toString(uint256(depthP));
        for (uint256 i = 0; i < DEPTH; i++) args[k++] = vm.toString(sibP[i]);

        args[k++] = vm.toString(uint256(depthC));
        for (uint256 i = 0; i < DEPTH; i++) args[k++] = vm.toString(sibC[i]);

        bytes memory out = vm.ffi(args);
        (proof, publicInputs) = abi.decode(out, (bytes, bytes32[]));
    }

    function _getReceiverProof(
        uint256 pk,
        address who,
        bytes32 nullS
    ) internal returns (bytes memory proof, bytes32[] memory publicInputs) {
        uint256 NUM_ARGS = 7;
        string[] memory args = new string[](NUM_ARGS);

        args[0] = "npx";
        args[1] = "tsx";
        args[2] = "js-scripts/generateProofReceiver.ts";
        args[3] = vm.toString(pk);
        args[4] = vm.toString(who);
        args[5] = vm.toString(EVENT_ID);
        args[6] = vm.toString(nullS);

        bytes memory out = vm.ffi(args);
        (proof, publicInputs) = abi.decode(out, (bytes, bytes32[]));
    }

    function _proofToFixed(
        bytes32[] memory siblings
    ) internal pure returns (bytes32[DEPTH] memory out, uint32 depthEff) {
        for (uint256 i = 0; i < DEPTH; i++) {
            out[i] = i < siblings.length ? siblings[i] : bytes32(0);
        }

        uint32 d;
        for (uint256 i = DEPTH; i > 0; i--) {
            if (out[i - 1] != bytes32(0)) {
                d = uint32(i);
                break;
            }
        }
        depthEff = d;
    }
}
