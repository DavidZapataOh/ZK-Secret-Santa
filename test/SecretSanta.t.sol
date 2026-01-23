// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";

import {Poseidon2} from "@poseidon/src/Poseidon2.sol";
import {Register} from "../src/Register.sol";
import {SantaFactory} from "../src/SantaFactory.sol";
import {SecretSanta} from "../src/SecretSanta.sol";
import {IVerifier} from "../src/verifiers/IVerifier.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {SparseMerkleTree} from "@solarity/contracts/libs/data-structures/SparseMerkleTree.sol";

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

    // ============================================
    // ========== CONSTRUCTOR TESTS ==============
    // ============================================

    function test_Constructor_InitializesCorrectly() public {
        (address evAddr, bytes32 evId) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);

        assertEq(address(ev.register()), address(reg));
        assertEq(address(ev.HASHER()), address(hasher));
        assertEq(address(ev.verifierSender()), address(vSender));
        assertEq(address(ev.verifierReceiver()), address(vReceiver));
        assertEq(ev.eventNonce(), 0);
        assertEq(ev.eventId(), evId);
        assertEq(ev.participantsSMTRoot(), reg.getRoot());
        assertEq(uint256(ev.status()), uint256(SecretSanta.EventStatus.COMMIT));
        assertEq(ev.commitmentsTreeDepth(), DEPTH);
    }

    function test_Constructor_RevertIf_RegistryNotFrozen() public {
        vm.prank(owner);
        reg.unfreeze();

        vm.expectRevert(SecretSanta.RegistryNotFrozen.selector);
        new SecretSanta(
            creator,
            reg,
            IVerifier(address(vSender)),
            IVerifier(address(vReceiver)),
            hasher,
            0,
            DEPTH
        );
    }

    // ============================================
    // ========== ADVANCE PHASE TESTS ============
    // ============================================

    function test_AdvancePhase_FromCommitToSendersDetermined() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);

        assertEq(uint256(ev.status()), uint256(SecretSanta.EventStatus.COMMIT));

        vm.prank(creator);
        ev.advancePhase();

        assertEq(uint256(ev.status()), uint256(SecretSanta.EventStatus.SENDERS_DETERMINED));
    }

    function test_AdvancePhase_FromSendersDeterminedToReceiversDisclosed() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);

        vm.prank(creator);
        ev.advancePhase();
        assertEq(uint256(ev.status()), uint256(SecretSanta.EventStatus.SENDERS_DETERMINED));

        vm.prank(creator);
        ev.advancePhase();
        assertEq(uint256(ev.status()), uint256(SecretSanta.EventStatus.RECEIVERS_DISCLOSED));
    }

    function test_AdvancePhase_FromReceiversDisclosedToCompleted() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);

        vm.prank(creator);
        ev.advancePhase();
        vm.prank(creator);
        ev.advancePhase();
        assertEq(uint256(ev.status()), uint256(SecretSanta.EventStatus.RECEIVERS_DISCLOSED));

        vm.prank(creator);
        ev.advancePhase();
        assertEq(uint256(ev.status()), uint256(SecretSanta.EventStatus.COMPLETED));
    }

    function test_AdvancePhase_NoChangeAfterCompleted() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);

        vm.startPrank(creator);
        ev.advancePhase();
        ev.advancePhase();
        ev.advancePhase();
        assertEq(uint256(ev.status()), uint256(SecretSanta.EventStatus.COMPLETED));

        ev.advancePhase();
        assertEq(uint256(ev.status()), uint256(SecretSanta.EventStatus.COMPLETED));
        vm.stopPrank();
    }

    function test_AdvancePhase_RevertIf_NotOwner() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);

        vm.prank(A);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, A));
        ev.advancePhase();
    }

    function test_AdvancePhase_EmitsEvent() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);

        vm.prank(creator);
        vm.expectEmit(false, false, false, true);
        emit SecretSanta.PhaseAdvanced(SecretSanta.EventStatus.SENDERS_DETERMINED);
        ev.advancePhase();
    }

    // ============================================
    // ======== COMMIT SIGNATURE TESTS ===========
    // ============================================

    function test_CommitSignature_Success() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);
        EVENT_ID = ev.eventId();

        (bytes32 H, ) = _getCommitmentAndNulls(pkA, A, EVENT_ID);

        vm.prank(A);
        ev.commitSignature(H);

        assertTrue(ev.commitmentUsed(A));
        assertEq(ev.commitmentOf(A), H);
    }

    function test_CommitSignature_EmitsEvent() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);
        EVENT_ID = ev.eventId();

        (bytes32 H, ) = _getCommitmentAndNulls(pkA, A, EVENT_ID);

        vm.prank(A);
        vm.expectEmit(true, false, false, true);
        emit SecretSanta.Commited(A, H, ev.commitmentsRoot());
        ev.commitSignature(H);
    }

    function test_CommitSignature_MultipleParticipants() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);
        EVENT_ID = ev.eventId();

        (bytes32 HA, ) = _getCommitmentAndNulls(pkA, A, EVENT_ID);
        (bytes32 HB, ) = _getCommitmentAndNulls(pkB, B, EVENT_ID);
        (bytes32 HC, ) = _getCommitmentAndNulls(pkC, C, EVENT_ID);

        vm.prank(A);
        ev.commitSignature(HA);
        vm.prank(B);
        ev.commitSignature(HB);
        vm.prank(C);
        ev.commitSignature(HC);

        assertTrue(ev.commitmentUsed(A));
        assertTrue(ev.commitmentUsed(B));
        assertTrue(ev.commitmentUsed(C));
        assertEq(ev.commitmentOf(A), HA);
        assertEq(ev.commitmentOf(B), HB);
        assertEq(ev.commitmentOf(C), HC);
    }

    function test_CommitSignature_RevertIf_WrongPhase() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);
        EVENT_ID = ev.eventId();

        vm.prank(creator);
        ev.advancePhase();

        (bytes32 H, ) = _getCommitmentAndNulls(pkA, A, EVENT_ID);

        vm.prank(A);
        vm.expectRevert(abi.encodeWithSelector(
            SecretSanta.InvalidEventStatus.selector,
            SecretSanta.EventStatus.SENDERS_DETERMINED
        ));
        ev.commitSignature(H);
    }

    function test_CommitSignature_RevertIf_NotRegistered() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);
        EVENT_ID = ev.eventId();

        address notRegistered = makeAddr("notRegistered");
        bytes32 fakeH = keccak256("fake");

        vm.prank(notRegistered);
        vm.expectRevert(SecretSanta.InvalidAddress.selector);
        ev.commitSignature(fakeH);
    }

    function test_CommitSignature_RevertIf_AlreadyCommitted() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);
        EVENT_ID = ev.eventId();

        (bytes32 H, ) = _getCommitmentAndNulls(pkA, A, EVENT_ID);

        vm.prank(A);
        ev.commitSignature(H);

        vm.prank(A);
        vm.expectRevert(SecretSanta.CommitmentAlreadyUsed.selector);
        ev.commitSignature(H);
    }

    // ============================================
    // ======= SENDER DETERMINATION TESTS ========
    // ============================================

    function test_SenderDetermination_Success() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);
        EVENT_ID = ev.eventId();

        (bytes32 HA, bytes32 nullA) = _commit(ev, pkA, A);

        vm.prank(creator);
        ev.advancePhase();

        ROOT_P = ev.participantsSMTRoot();
        ROOT_C = ev.commitmentsRoot();

        _determineSender(ev, pkA, A, HA);

        assertEq(ev.sendersCount(), 1);
        assertTrue(ev.spentSenderNulls(nullA));

        (bytes32 r, bytes32 storedNulls) = ev.giftSenders(0);
        assertEq(storedNulls, nullA);
        assertTrue(r != bytes32(0));
    }

    function test_SenderDetermination_MultipleSenders() public {
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

        assertEq(ev.sendersCount(), 3);
        assertTrue(ev.spentSenderNulls(nullA));
        assertTrue(ev.spentSenderNulls(nullB));
        assertTrue(ev.spentSenderNulls(nullC));
    }

    function test_SenderDetermination_RevertIf_WrongPhase() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);
        EVENT_ID = ev.eventId();

        bytes32[] memory fakeInputs = new bytes32[](6);

        vm.expectRevert(abi.encodeWithSelector(
            SecretSanta.InvalidEventStatus.selector,
            SecretSanta.EventStatus.COMMIT
        ));
        ev.senderDetermination(hex"", fakeInputs);
    }

    function test_SenderDetermination_RevertIf_InvalidPublicInputsLength() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);

        vm.prank(creator);
        ev.advancePhase();

        bytes32[] memory wrongInputs = new bytes32[](3);

        vm.expectRevert(SecretSanta.InvalidPublicInputs.selector);
        ev.senderDetermination(hex"", wrongInputs);
    }

    function test_SenderDetermination_RevertIf_InvalidEventId() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);

        vm.prank(creator);
        ev.advancePhase();

        bytes32[] memory inputs = new bytes32[](6);
        inputs[0] = bytes32(uint256(1)); // r
        inputs[1] = bytes32(uint256(0)); // eventId hi (wrong)
        inputs[2] = bytes32(uint256(0)); // eventId lo (wrong)
        inputs[3] = ev.participantsSMTRoot();
        inputs[4] = ev.commitmentsRoot();
        inputs[5] = bytes32(uint256(123)); // nulls

        vm.expectRevert(abi.encodeWithSelector(
            SecretSanta.InvalidEventId.selector,
            bytes32(0)
        ));
        ev.senderDetermination(hex"", inputs);
    }

    function test_SenderDetermination_EmitsEvent() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);
        EVENT_ID = ev.eventId();

        (bytes32 HA, bytes32 nullA) = _commit(ev, pkA, A);

        vm.prank(creator);
        ev.advancePhase();

        ROOT_P = ev.participantsSMTRoot();
        ROOT_C = ev.commitmentsRoot();

        bytes32 keyP = reg.keyOf(A);
        bytes32[] memory sibPdyn = reg.getProof(keyP).siblings;
        bytes32[] memory sibCdyn = ev.getCommitmentProof(HA).siblings;

        (bytes32[DEPTH] memory sibP, uint32 depthP) = _proofToFixed(sibPdyn);
        (bytes32[DEPTH] memory sibC, uint32 depthC) = _proofToFixed(sibCdyn);

        (bytes memory proof, bytes32[] memory pub) = _getSenderProof(
            pkA, A, sibP, depthP, sibC, depthC
        );

        vm.expectEmit(false, false, false, true);
        emit SecretSanta.SenderDetermined(pub[0], nullA, 0);
        ev.senderDetermination(proof, pub);
    }

    // ============================================
    // ======= RECEIVER DISCLOSURE TESTS =========
    // ============================================

    function test_ReceiverDisclosure_Success() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);
        EVENT_ID = ev.eventId();

        (bytes32 HA, bytes32 nullA) = _commit(ev, pkA, A);
        (bytes32 HB, bytes32 nullB) = _commit(ev, pkB, B);

        vm.prank(creator);
        ev.advancePhase();

        ROOT_P = ev.participantsSMTRoot();
        ROOT_C = ev.commitmentsRoot();

        _determineSender(ev, pkA, A, HA);
        _determineSender(ev, pkB, B, HB);

        vm.prank(creator);
        ev.advancePhase();

        bytes memory payload = abi.encodePacked(bytes32(uint256(999)));
        _disclose(ev, pkA, A, nullB, payload);

        assertTrue(ev.receiverDisclosed(A));
        assertTrue(ev.chosenSenderNulls(nullB));
        assertEq(keccak256(ev.getPayloadForSender(nullB)), keccak256(payload));
    }

    function test_ReceiverDisclosure_MultipleReceivers() public {
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

        assertTrue(ev.receiverDisclosed(A));
        assertTrue(ev.receiverDisclosed(B));
        assertTrue(ev.receiverDisclosed(C));
    }

    function test_ReceiverDisclosure_RevertIf_WrongPhase() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);

        bytes32[] memory fakeInputs = new bytes32[](4);

        vm.prank(A);
        vm.expectRevert(abi.encodeWithSelector(
            SecretSanta.InvalidEventStatus.selector,
            SecretSanta.EventStatus.COMMIT
        ));
        ev.receiverDisclosure(hex"", fakeInputs, hex"");
    }

    function test_ReceiverDisclosure_RevertIf_NotRegistered() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);

        vm.prank(creator);
        ev.advancePhase();
        vm.prank(creator);
        ev.advancePhase();

        address notRegistered = makeAddr("notRegistered");
        bytes32[] memory fakeInputs = new bytes32[](4);

        vm.prank(notRegistered);
        vm.expectRevert(abi.encodeWithSelector(
            SecretSanta.ParticipantNotRegistered.selector,
            notRegistered
        ));
        ev.receiverDisclosure(hex"", fakeInputs, hex"");
    }

    function test_ReceiverDisclosure_RevertIf_InvalidPublicInputsLength() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);

        vm.prank(creator);
        ev.advancePhase();
        vm.prank(creator);
        ev.advancePhase();

        bytes32[] memory wrongInputs = new bytes32[](2);

        vm.prank(A);
        vm.expectRevert(SecretSanta.InvalidPublicInputs.selector);
        ev.receiverDisclosure(hex"", wrongInputs, hex"");
    }

    // ============================================
    // =========== VIEW FUNCTIONS TESTS ==========
    // ============================================

    function test_CommitmentsRoot_InitiallyNonZero() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);

        bytes32 root = ev.commitmentsRoot();
        assertTrue(root != bytes32(0));
    }

    function test_CommitmentsRoot_ChangesAfterCommit() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);
        EVENT_ID = ev.eventId();

        bytes32 rootBefore = ev.commitmentsRoot();

        (bytes32 H, ) = _getCommitmentAndNulls(pkA, A, EVENT_ID);
        vm.prank(A);
        ev.commitSignature(H);

        bytes32 rootAfter = ev.commitmentsRoot();
        assertTrue(rootBefore != rootAfter);
    }

    function test_SendersCount_InitiallyZero() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);

        assertEq(ev.sendersCount(), 0);
    }

    function test_SendersCount_IncreasesAfterDetermination() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);
        EVENT_ID = ev.eventId();

        (bytes32 HA, ) = _commit(ev, pkA, A);

        vm.prank(creator);
        ev.advancePhase();

        ROOT_P = ev.participantsSMTRoot();
        ROOT_C = ev.commitmentsRoot();

        assertEq(ev.sendersCount(), 0);
        _determineSender(ev, pkA, A, HA);
        assertEq(ev.sendersCount(), 1);
    }

    function test_GetPayloadForSender_ReturnsEmptyIfNotSet() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);

        bytes memory payload = ev.getPayloadForSender(bytes32(uint256(123)));
        assertEq(payload.length, 0);
    }

    function test_GetCommitmentProof_ReturnsValidProof() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);
        EVENT_ID = ev.eventId();

        (bytes32 H, ) = _getCommitmentAndNulls(pkA, A, EVENT_ID);
        vm.prank(A);
        ev.commitSignature(H);

        SparseMerkleTree.Proof memory proof = ev.getCommitmentProof(H);
        assertTrue(proof.siblings.length > 0);
    }

    function test_ParticipantsSMTRoot_MatchesRegistry() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);

        assertEq(ev.participantsSMTRoot(), reg.getRoot());
    }

    function test_EventId_IsCorrectlyComputed() public {
        (address evAddr, bytes32 expectedId) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);

        assertEq(ev.eventId(), expectedId);
        assertEq(ev.eventId(), keccak256(abi.encodePacked(evAddr, uint256(0))));
    }

    // ============================================
    // ========== MAPPING STATE TESTS ============
    // ============================================

    function test_CommitmentUsed_FalseByDefault() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);

        assertFalse(ev.commitmentUsed(A));
        assertFalse(ev.commitmentUsed(B));
        assertFalse(ev.commitmentUsed(C));
    }

    function test_CommitmentOf_ZeroByDefault() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);

        assertEq(ev.commitmentOf(A), bytes32(0));
    }

    function test_SpentSenderNulls_FalseByDefault() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);

        assertFalse(ev.spentSenderNulls(bytes32(uint256(123))));
    }

    function test_ChosenSenderNulls_FalseByDefault() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);

        assertFalse(ev.chosenSenderNulls(bytes32(uint256(123))));
    }

    function test_ReceiverDisclosed_FalseByDefault() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);

        assertFalse(ev.receiverDisclosed(A));
    }

    function test_SenderIndexPlus1ByNulls_ZeroByDefault() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);

        assertEq(ev.senderIndexPlus1ByNulls(bytes32(uint256(123))), 0);
    }

    function test_SenderIndexPlus1ByNulls_SetAfterDetermination() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);
        EVENT_ID = ev.eventId();

        (bytes32 HA, bytes32 nullA) = _commit(ev, pkA, A);

        vm.prank(creator);
        ev.advancePhase();

        ROOT_P = ev.participantsSMTRoot();
        ROOT_C = ev.commitmentsRoot();

        _determineSender(ev, pkA, A, HA);

        assertEq(ev.senderIndexPlus1ByNulls(nullA), 1);
    }

    // ============================================
    // ============ IMMUTABLE TESTS ==============
    // ============================================

    function test_Immutables_AreSetCorrectly() public {
        (address evAddr, ) = _createEvent();
        SecretSanta ev = SecretSanta(evAddr);

        assertEq(address(ev.register()), address(reg));
        assertEq(address(ev.HASHER()), address(hasher));
        assertEq(address(ev.verifierSender()), address(vSender));
        assertEq(address(ev.verifierReceiver()), address(vReceiver));
        assertEq(ev.commitmentsTreeDepth(), DEPTH);
    }

    // ============================================
    // ============= HELPERS =====================
    // ============================================

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
