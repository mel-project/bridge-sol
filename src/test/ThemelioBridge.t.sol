// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.10;

import 'ds-test/test.sol';
import '../ThemelioBridge.sol';

contract ThemelioRelayTest is DSTest {
    ThemelioBridge bridge;
    Blake3Sol blake3;

    function setUp() public {
        bridge = new ThemelioBridge();
        blake3 = new Blake3Sol();
    }

    function testBlake3() public {
        Hasher memory hasher = blake3.new_hasher();
        hasher = blake3.update_hasher(hasher, unicode'hellohello?');
        bytes memory output = blake3.finalize(hasher);

        assertEq(
            bytes32(output),
            0x10e6acb2cfcc4bb07588ad5b8e85f6a13f19e24f3302826effd93ce1ebbece6e
        );
    }

    function testHashLeaf() public {
        assertEq(
            bridge.hashLeaf(abi.encodePacked('datablock')),
            0x6ccea12fef78d2af66a4bca268cdbeccc47b3ee3ec9fbf83da1a67b526e9da2e
        );
    }

    function testHashNode() public {
        assertEq(
            bridge.hashNodes(abi.encodePacked('node')),
            0x7b568d1038ae40d3683670f02841d47a11794b6a629c2c02fedd5856e868cc2b
        );
    }

    function testRelayHeader() public {
        ThemelioBridge.Header memory header = ThemelioBridge.Header(
            0xff,
            0x9bfb7b21c884b2bbafc999275b3c66eb08af3fb95dd615eea0cd7554ce7709ce,
            438469,
            0xad746b334b83634c0b24c85238bdc982c90576db984a8f6411e7ef05aa776b6d,
            0xc36524f2ee84cad7751099e7736f5513f18cb2be98467ac5813ed7905d1057a6,
            0x1cc3e4775bb50924a20e49c6835e663296543bbe7417512645a9e02147447b69,
            9987237428,
            1003,
            22369621,
            0x7d97fbf0afe5facfb25f803527bf0e8cefe26dd3146fe3889a43d1fd4a347f88,
            0x92707d70a55d32778eced56feb672a3e25a8dc5d5278adb542e61edd2f2d3f44,
            0x4fDD02c537AA4cAB34b4a89740Ef516938e5dfEc
        );

        bridge.relayHeader(header);

        (
            bytes1 netId,
            bytes32 previous,
            uint64 height,
            bytes32 historyHash,
            bytes32 coinsHash,
            bytes32 transactionsHash,
            uint128 feePool,
            uint128 feeMultiplier,
            uint128 doscSpeed,
            bytes32 poolsHash,
            bytes32 stakeDocHash,
            address relayer
        ) = bridge.headers(438469);

        assertEq(transactionsHash, header.transactionsHash);
    }

    function testComputeMerkleRoot() public {
        bytes32 txHash = bridge.hashLeaf(abi.encodePacked(
            bytes32(0x5101ccec6db0372f89da31ff8abe159565ec03a7f44090e1bee8eb8c1431a7a3),
            bytes32(0xd0d10102a27607c66bc1ee1cbe054db137072bb6810a0af0c2c26352c8aa2854),
            bytes32(0xa4c28368fca0860100016d00a27607c66bc1ee1cbe054db137072bb6810a0af0),
            bytes32(0xc2c26352c8aa2854a4c28368fc6c80b3eb016d001701a2343230303039663130),
            bytes32(0x3030303030303030303030303030303030303030303030303030303030303030),
            bytes32(0x3030303030303030303030303030303030303030303030303030303030303634),
            bytes32(0x3230303030353035306630323065313462616633323930383231666432333464),
            bytes32(0x3562346531356665376661303464633166646137613461623634653538383339),
            bytes32(0x65333565363962353664386665343230303031333230303230023733014033fb),
            bytes32(0x3834ba3ccae482bd733f516d2233a23629c45a3ef81e5782af12d29824a14674),
            bytes30(0x272e6c25bda6d37752725215f13f55f393b9b3fee7e15594ffa1ed29d70b)
        ));
        uint256 txIndex = 1;
        bytes32[] memory proof = new bytes32[](3);

        proof[0] = bytes32(0x8e23d629378af3f260a06239876d07a00df5b3c64c2cbf1361402db735486847);
        proof[1] = bytes32(0xb2772a61ca1750e7d628fb44ce64cfcc1bf6f9293ded3e73bf85c3a5960bb4b4);
        proof[2] = bytes32(0xb6c263510f89558cf64f094899e7ce7e9d50b11fad02f5ee20a10bb07a67b47f);

        assertEq(
            bridge.computeMerkleRoot(txHash, txIndex, proof),
            bytes32(0x1cc3e4775bb50924a20e49c6835e663296543bbe7417512645a9e02147447b69)
        );
    }

    function testVerifyTx() public {
        ThemelioBridge.Header memory header = ThemelioBridge.Header(
            0xff,
            0x9bfb7b21c884b2bbafc999275b3c66eb08af3fb95dd615eea0cd7554ce7709ce,
            438469,
            0xad746b334b83634c0b24c85238bdc982c90576db984a8f6411e7ef05aa776b6d,
            0xc36524f2ee84cad7751099e7736f5513f18cb2be98467ac5813ed7905d1057a6,
            0x1cc3e4775bb50924a20e49c6835e663296543bbe7417512645a9e02147447b69,
            9987237428,
            1003,
            22369621,
            0x7d97fbf0afe5facfb25f803527bf0e8cefe26dd3146fe3889a43d1fd4a347f88,
            0x92707d70a55d32778eced56feb672a3e25a8dc5d5278adb542e61edd2f2d3f44,
            0x4fDD02c537AA4cAB34b4a89740Ef516938e5dfEc
        );

        bridge.relayHeader(header);

        (
            bytes1 netId,
            bytes32 previous,
            uint64 height,
            bytes32 historyHash,
            bytes32 coinsHash,
            bytes32 transactionsHash,
            uint128 feePool,
            uint128 feeMultiplier,
            uint128 doscSpeed,
            bytes32 poolsHash,
            bytes32 stakeDocHash,
            address relayer
        ) = bridge.headers(438469);

        bytes memory rawTx = abi.encodePacked(
            bytes32(0x5101ccec6db0372f89da31ff8abe159565ec03a7f44090e1bee8eb8c1431a7a3),
            bytes32(0xd0d10102a27607c66bc1ee1cbe054db137072bb6810a0af0c2c26352c8aa2854),
            bytes32(0xa4c28368fca0860100016d00a27607c66bc1ee1cbe054db137072bb6810a0af0),
            bytes32(0xc2c26352c8aa2854a4c28368fc6c80b3eb016d001701a2343230303039663130),
            bytes32(0x3030303030303030303030303030303030303030303030303030303030303030),
            bytes32(0x3030303030303030303030303030303030303030303030303030303030303634),
            bytes32(0x3230303030353035306630323065313462616633323930383231666432333464),
            bytes32(0x3562346531356665376661303464633166646137613461623634653538383339),
            bytes32(0x65333565363962353664386665343230303031333230303230023733014033fb),
            bytes32(0x3834ba3ccae482bd733f516d2233a23629c45a3ef81e5782af12d29824a14674),
            bytes30(0x272e6c25bda6d37752725215f13f55f393b9b3fee7e15594ffa1ed29d70b)
        );
        uint256 txIndex = 1;
        uint256 blockHeight = 438469;
        bytes32[] memory proof = new bytes32[](3);

        proof[0] = bytes32(0x8e23d629378af3f260a06239876d07a00df5b3c64c2cbf1361402db735486847);
        proof[1] = bytes32(0xb2772a61ca1750e7d628fb44ce64cfcc1bf6f9293ded3e73bf85c3a5960bb4b4);
        proof[2] = bytes32(0xb6c263510f89558cf64f094899e7ce7e9d50b11fad02f5ee20a10bb07a67b47f);

        assertTrue(bridge.verifyTx(rawTx, txIndex, blockHeight, proof));
    }
}