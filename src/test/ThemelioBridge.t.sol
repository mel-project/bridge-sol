// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.10;

import 'ds-test/test.sol';
import '../ThemelioBridge.sol';

contract ThemelioBridgeTest is DSTest, ThemelioBridge {
    // for external calls
    ThemelioBridge bridge;
    
    function setUp() public {
        bridge = new ThemelioBridge();
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
            hashLeaf(abi.encodePacked('datablock')),
            0x6ccea12fef78d2af66a4bca268cdbeccc47b3ee3ec9fbf83da1a67b526e9da2e
        );
    }

    function testHashNode() public {
        assertEq(
            hashNodes(abi.encodePacked('node')),
            0x7b568d1038ae40d3683670f02841d47a11794b6a629c2c02fedd5856e868cc2b
        );
    }

    function testRelayHeader() public {}

    function testComputeMerkleRoot() public {}

    function testVerifyTx() public {}

    function decodeIntegerTest(bytes calldata header, uint256 offset) public pure returns (uint256) {
        uint256 integer = decodeInteger(header, offset);

        return integer;
    }

    function testEncodedIntegerSize() public {
        // 250 with no padding
        bytes memory oneByteInteger = abi.encodePacked(bytes1(0xfa));
        uint256 oneByteSize = encodedIntegerSize(oneByteInteger, 0);
        assertEq(oneByteSize, 1);

        // 251 with 1 byte of padding on both sides
        bytes memory threeByteInteger = abi.encodePacked(bytes5(0xfffbfb00ff));
        uint256 threeByteSize = encodedIntegerSize(threeByteInteger, 1);
        assertEq(threeByteSize, 3);

        // 2**16 with 2 bytes of padding on both sides
        bytes memory fiveByteInteger = abi.encodePacked(bytes9(0xfffffc00000100ffff));
                uint256 fiveByteSize = encodedIntegerSize(fiveByteInteger, 2);
        assertEq(fiveByteSize, 5);

        // 2**32 with 3 bytes of padding on both sides
        bytes memory nineByteInteger = abi.encodePacked(bytes15(0xfffffffd0000000001000000ffffff));
        uint256 nineByteSize = encodedIntegerSize(nineByteInteger, 3);
        assertEq(nineByteSize, 9);

        // 2**64 with 4 bytes of padding on both sides
        bytes memory seventeenByteInteger = abi.encodePacked(bytes25(0xfffffffffe00000000000000000100000000000000ffffffff));
        uint256 seventeenByteSize = encodedIntegerSize(seventeenByteInteger, 4);
        assertEq(seventeenByteSize, 17);
    }

    function testExtractMerkleRoot() public {
        bytes memory header = abi.encodePacked(
            bytes32(0xff6b91090007737cd4cc72ac2067ab3441218f0977d00039c2363867bafd2e44),
            bytes32(0xf4fda84c8c112efd7da407a7bbab3660ca201e02b3ac54ea0775839e2fb4b4f6),
            bytes32(0xf458ebef7d1bb11fff52cd0b0d522541a034493c8bce35d5c78616da0644b758),
            bytes32(0x8980bc3fd95e678b2155cc31bac5a1ce87db5f32c719f5209984d6aea2582981),
            bytes32(0x0b153d97ddb22b004f9efec8ffe0630521d94ec973dea0a1369884fec037ff47),
            bytes32(0xba4c2d0ba0167d711026711ffe026c833667f9a7602473a7b5053d4d3798d768),
            bytes32(0x161cc8276a1dcfcf68a4b63b85f9960ef20792d8260e16eb93620066c905bba0),
            bytes29(0x71d65be9bc30b11a68a0819886d2ce85b9414e00719a706a77d8bc0772)
        );
        bytes32 merkleRoot = extractMerkleRoot(header);

        assertEq(merkleRoot, bytes32(0xcc31bac5a1ce87db5f32c719f5209984d6aea25829810b153d97ddb22b004f9e));
    }

    function extractBlockHeightTest(bytes calldata header) public returns (uint256) {
        uint256 blockHeight = extractBlockHeight(header);

        return blockHeight;
    }

    function testExtractValueAndRecipient() public {}

    function testExtractTokenType() public {}
}

contract ThemelioBridgeTestInternalCalldata is DSTest {
    ThemelioBridgeTest bridgeTest;

    function setUp() public {
        bridgeTest = new ThemelioBridgeTest();
    }

    function testDecodeIntegerHelper() public {
        bytes memory header0 = abi.encodePacked(
            bytes1(0xfa)
        );
        uint256 integer0 = bridgeTest.decodeIntegerTest(header0, 0);
        uint256 int0 = 0xfa;
        assertEq(integer0, int0);

        bytes memory header1 = abi.encodePacked(
            bytes4(0x00fb1111)
        );
        uint256 integer1 = bridgeTest.decodeIntegerTest(header1, 1);
        uint256 int1 = 0x1111;
        assertEq(integer1, int1);

        bytes memory header2 = abi.encodePacked(
            bytes7(0x0000fc22222222)
        );
        uint256 integer2 = bridgeTest.decodeIntegerTest(header2, 2);
        uint256 int2 = 0x22222222;
        assertEq(integer2, int2);

        bytes memory header3 = abi.encodePacked(
            bytes12(0x000000fd3333333333333333)
        );
        uint256 integer3 = bridgeTest.decodeIntegerTest(header3, 3);
        uint256 int3 = 0x3333333333333333;
        assertEq(integer3, int3);

        bytes memory header4 = abi.encodePacked(
            bytes21(0x00000000fe44444444444444444444444444444444)
        );
        uint256 integer4 = bridgeTest.decodeIntegerTest(header4, 4);
        uint256 int4 = 0x44444444444444444444444444444444;
        assertEq(integer4, int4);
    }

    function testExtractBlockHeightHelper() public {
        bytes memory header = abi.encodePacked(
            bytes32(0xff2886e61b7756ec3fd75b0f89f3dc8d8dd2f7b44401c4e2fb55cc037980e44b),
            bytes32(0xbafd5928e58213d64dc5f1d25074f72f9e1457562e45913d8eb2ed461e1396be),
            bytes32(0x39ca087bb7de7c178811418f7da89b5e89e56ade852bc77909f5043339c1b8cc),
            bytes32(0x4b0d2060e16b824a8f44e53545413058167cef39efc8a9da6d3a620d1719fd91),
            bytes32(0x0c081d64a0f698d153cefefbffffca93a032754fe28625fc5239e5fe94c2ae0a),
            bytes32(0xef2efde355dc11aff5446783feb859bcadd36dbe0ed6e6d9d0f13d41f68fd2d0),
            bytes32(0x6c66cd36ba998c346e481522724ff71b19c04e8841616bf2afe880ca063b232b),
            bytes29(0x90a52d3801d0d9775ac49ee59050d115aeff4796c9e3d11bc010341590)
        );
        uint256 blockHeight = bridgeTest.extractBlockHeightTest(header);

        assertEq(blockHeight, 14217254977967302745);
    }

// expected: 14217254977967302745
// hex: c54dd61382e52859
// encoded: fd5928e58213d64dc5

// actual: 6424637215285333445
// hex: 5928e58213d64dc5
// encoded: fdc54dd61382e52859
}