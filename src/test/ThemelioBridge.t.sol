// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.10;

import "ds-test/test.sol";
import "../ThemelioBridge.sol";

contract ThemelioRelayTest is DSTest {
    ThemelioBridge bridge;
    Blake3Sol blake3;

    function setUp() public {
        bridge = new ThemelioBridge();
        blake3 = new Blake3Sol();
    }

    function testBlake3() public {
        Hasher memory hasher  = blake3.new_hasher();
        Hasher memory hasher1 = blake3.update_hasher(hasher, unicode"hellohello?");
        bytes memory output = blake3.finalize(hasher1);

        assertEq(
            bytes32(output),
            0x10e6acb2cfcc4bb07588ad5b8e85f6a13f19e24f3302826effd93ce1ebbece6e
        );
    }

    function testComputeMerkleRoot() public {
        bytes32 txHash;
        uint256 txIndex;
        bytes memory proof;

        bridge.computeMerkleRoot(txHash, txIndex, proof);
    }

    function testVerifyTx() public {
        bytes memory rawTx;
        uint256 txIndex;
        uint256 blockHeight;
        bytes memory proof;

        bridge.verifyTx(rawTx, txIndex, blockHeight, proof);
    }
}
