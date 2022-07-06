// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.13;

import 'forge-std/Test.sol';
import 'openzeppelin-contracts/contracts/utils/Strings.sol';
import './utils/ByteStrings.sol';
import '../ThemelioBridge.sol';

contract ThemelioBridgeTestFFI is ThemelioBridge, Test {
    using Blake3Sol for Blake3Sol.Hasher;
    using ByteStrings for bytes;
    using Strings for uint256;

        /* =========== Helpers =========== */

    function computeMerkleRootHelper(
        bytes32 txHash,
        uint256 index,
        bytes32[] calldata proof
    ) public pure returns (bytes32) {
        bytes32 merkleRoot = _computeMerkleRoot(txHash, index, proof);

        return merkleRoot;
    }

    function decodeHeaderHelper(
        bytes calldata header_
    ) public pure returns (uint256, bytes32, bytes32) {
        (
            uint256 blockHeight,
            bytes32 transactionsHash,
            bytes32 stakesHash
        ) = _decodeHeader(header_);

        return (
            blockHeight,
            transactionsHash,
            stakesHash
        );
    }

    function decodeStakeDocHelper(bytes calldata encodedStakeDoc_)
        public pure returns (bytes32, uint256, uint256, uint256) {
        (StakeDoc memory decodedStakeDoc,) = _decodeStakeDoc(encodedStakeDoc_, 0);

        return (
            decodedStakeDoc.publicKey,
            decodedStakeDoc.epochStart,
            decodedStakeDoc.epochPostEnd,
            decodedStakeDoc.symsStaked
        );
    }

    function decodeTransactionHelper() public {

    }

    function denomToStringHelper(uint256 denom) public pure returns (string memory) {
        if (denom == MEL) {
            return "MEL";
        } else if (denom == SYM) {
            return "SYM";
        } else if (denom == ERG) {
            return "ERG";
        } else if (denom == NEWCOIN) {
            return "(NEWCOIN)";
        } else {
            string memory txHash = abi.encodePacked(denom).toHexString();
            txHash = string(_slice(abi.encodePacked(txHash), 2, 66));

            return string(abi.encodePacked("CUSTOM-", txHash));
        }
    }

    function hashDatablockHelper(bytes calldata data) public pure returns (bytes32) {
        bytes32 dataHash = _hashDatablock(data);

        return dataHash;
    }

    function mintHelper(address account, uint256 id, uint256 value) public {
        _mint(account, id, value, '');
    }

    function verifyHeaderHelper(
        bytes32 verifierStakesHash,
        uint256 verifierHeight
    ) public {
        headers[verifierHeight].stakesHash = verifierStakesHash;
    }

    function verifyTxHelper(
        uint256 blockHeight,
        bytes32 transactionsHash,
        bytes32 stakesHash
    ) public {
        headers[blockHeight].transactionsHash = transactionsHash;
        headers[blockHeight].stakesHash = stakesHash;
    }

        /* =========== Differential FFI Fuzz Tests =========== */

    function testBlake3DifferentialFFI(bytes memory data) public {
        string[] memory cmds = new string[](3);

        cmds[0] = './src/test/differentials/target/debug/bridge_differential_tests';
        cmds[1] = '--blake3';
        cmds[2] = data.toHexString();

        bytes memory result = vm.ffi(cmds);
        bytes32 rustHash = abi.decode(result, (bytes32));

        bytes32 solHash = _hashNodes(data);

        assertEq(solHash, rustHash);
    }

    function testEd25519DifferentialFFI(bytes memory message) public {
        string[] memory cmds = new string[](3);

        cmds[0] = './src/test/differentials/target/debug/bridge_differential_tests';
        cmds[1] = '--ed25519';
        cmds[2] = message.toHexString();

        bytes memory result = vm.ffi(cmds);

        (bytes32 signer, bytes32 r, bytes32 S) = abi.decode(result, (bytes32, bytes32, bytes32));

        assertTrue(Ed25519.verify(signer, r, S, message));
    }

    function testDecodeIntegerDifferentialFFI(uint128 integer) public {
        string[] memory cmds = new string[](3);

        cmds[0] = './src/test/differentials/target/debug/bridge_differential_tests';
        cmds[1] = '--decode-integer';
        cmds[2] = uint256(integer).toString();

        bytes memory result = vm.ffi(cmds);

        (bytes memory resultsInteger, uint256 resultsIntegerSize) = abi.decode(result, (bytes, uint256));

        (uint256 decodedInteger, uint256 decodedIntegerSize) = _decodeInteger(resultsInteger, 0);

        assertEq(decodedInteger, integer);
        assertEq(decodedIntegerSize, resultsIntegerSize);
    }

    function testKeccakBigHashFFI() public {
        string[] memory cmds = new string[](2);
        cmds[0] = './src/test/differentials/target/debug/bridge_differential_tests';
        cmds[1] = '--big-hash';

        bytes memory packedData = vm.ffi(cmds);
        (bytes memory data,) = abi.decode(packedData, (bytes, bytes32));

        keccak256(data);
    }

    function testSliceDifferentialFFI(bytes memory data, uint8 start, uint8 end) public {
        uint256 dataLength = data.length;

        if (start <= end) {
            vm.assume(start >= 0 && end <= dataLength);
        } else {
            vm.assume(start < dataLength && end >= 0);
        }

        string[] memory cmds = new string[](7);

        cmds[0] = './src/test/differentials/target/debug/bridge_differential_tests';
        cmds[1] = '--slice';
        cmds[2] = data.toHexString();
        cmds[3] = '--start';
        cmds[4] = uint256(start).toString();
        cmds[5] = '--end';
        cmds[6] = uint256(end).toString();

        bytes memory result = vm.ffi(cmds);

        bytes memory slice = _slice(data, start, end);

        assertEq(slice, result);
    }
}

// contract for tests involving internal functions that have calldata params
contract ThemelioBridgeTestInternalCalldataFFI is Test {
    using Strings for uint;
    using ByteStrings for bytes;

    uint256 constant STAKE_EPOCH = 200_000;

    uint256 constant MEL = 0;
    uint256 constant SYM = 1;

    ThemelioBridgeTestFFI bridgeTest;

    function setUp() public {
        bridgeTest = new ThemelioBridgeTestFFI();
    }

        /* =========== Differential Fuzz and FFI Tests =========== */

    function testBigHashFFI() public {
        string[] memory cmds = new string[](2);
        cmds[0] = './src/test/differentials/target/debug/bridge_differential_tests';
        cmds[1] = '--big-hash';

        bytes memory packedData = vm.ffi(cmds);
        (bytes memory data, bytes32 dataHash) = abi.decode(packedData, (bytes, bytes32));

        bytes32 bigHash = bridgeTest.hashDatablockHelper(data);

        assertEq(bigHash, dataHash);
    }

    // function testExtractBlockHeightDifferentialFFI(uint128 modifierNum, uint64 blockHeight) public {
    //     string[] memory cmds = new string[](5);

    //     cmds[0] = './src/test/differentials/target/debug/bridge_differential_tests';
    //     cmds[1] = '--extract-block-height';
    //     cmds[2] = uint256(blockHeight).toString();
    //     cmds[3] = '--modifier';
    //     cmds[4] = uint256(modifierNum).toString();

    //     bytes memory header = vm.ffi(cmds);

    //     uint256 extractedBlockHeight = bridgeTest.extractBlockHeightHelper(header);

    //     assertEq(extractedBlockHeight, blockHeight);
    // }

    // function testExtractTransactionsHashDifferentialFFI(uint128 modifierNum) public {
    //     string[] memory cmds = new string[](3);

    //     cmds[0] = './src/test/differentials/target/debug/bridge_differential_tests';
    //     cmds[1] = '--extract-transactions-hash';
    //     cmds[2] = uint256(modifierNum).toString();

    //     bytes memory result = vm.ffi(cmds);

    //     (bytes memory header, bytes32 merkleRoot) = abi.decode(result, (bytes, bytes32));

    //     bytes32 extractedTransactionsHash = bridgeTest.extractTransactionsHashHelper(header);

    //     assertEq(extractedTransactionsHash, merkleRoot);
    // }

    // function testExtractValueDenomAndRecipientDifferentialFFI(
    //     uint128 value,
    //     uint256 denom,
    //     address recipient
    // ) public {
    //     string[] memory cmds = new string[](7);

    //     cmds[0] = './src/test/differentials/target/debug/bridge_differential_tests';
    //     cmds[1] = '--extract-value';
    //     cmds[2] = uint256(value).toString();
    //     cmds[3] = '--denom';
    //     cmds[4] = bridgeTest.denomToStringHelper(denom);
    //     cmds[5] = '--recipient';
    //     cmds[6] = abi.encodePacked(recipient).toHexString();

    //     bytes memory header = vm.ffi(cmds);

    //     (
    //         uint256 extractedValue,
    //         uint256 extractedDenom,
    //         address extractedRecipient
    //     ) = bridgeTest.extractValueDenomAndRecipientHelper(header);

    //     assertEq(extractedValue, value);
    //     assertEq(extractedDenom, denom);
    //     assertEq(extractedRecipient, recipient);
    // }

    function testVerifyHeaderDifferentialFFI(uint8 numStakeDocs) public {
        vm.assume(numStakeDocs != 0 && numStakeDocs < 90);

        string[] memory cmds = new string[](3);
        cmds[0] = './src/test/differentials/target/debug/bridge_differential_tests';
        cmds[1] = '--verify-header';
        cmds[2] = uint256(numStakeDocs).toString();

        bytes memory data = vm.ffi(cmds);

        (
            uint256 verifierHeight,
            bytes32 verifierStakesHash,
            bytes memory header,
            bytes memory stakeDocs,
            bytes32[] memory signatures
        ) = abi.decode(data, (uint256, bytes32, bytes, bytes, bytes32[]));

        bridgeTest.verifyHeaderHelper(verifierStakesHash, verifierHeight);

        bool success;

        success = bridgeTest.verifyHeader{gas: 25_000_000}(
            verifierHeight,
            header,
            stakeDocs,
            signatures,
            true
        );

        while (!success) {
            success = bridgeTest.verifyHeader{gas: 25_000_000}(
                verifierHeight,
                header,
                stakeDocs,
                signatures,
                false
            );
        }

        assertTrue(success);
    }
}