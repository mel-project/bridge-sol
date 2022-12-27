// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.16;

import 'forge-std/Test.sol';
import 'openzeppelin-contracts/contracts/utils/Strings.sol';
import './utils/ByteStrings.sol';
import '../ThemelioBridge.sol';

string constant FFI_PATH = './src/test/differentials/target/debug/bridge_differential_tests';

uint256 constant GAS_LIMIT = 27_000_000;
uint256 constant VERIFICATION_LIMIT = 24;

contract ThemelioBridgeTestFFI is ThemelioBridge, Test {
    using Blake3Sol for Blake3Sol.Hasher;
    using ByteStrings for bytes;
    using Strings for uint256;

        /* =========== Helpers =========== */

    function computeMerkleRootHelper(
        bytes32 txHash_,
        uint256 index_,
        bytes32[] calldata proof_
    ) public pure returns (bytes32) {
        bytes32 merkleRoot = _computeMerkleRoot(txHash_, index_, proof_);

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

    function decodeIntegerHelper(
        bytes calldata data,
        uint256 offset
    ) public pure returns (uint256, uint256) {
        (uint256 integer, uint256 length) = _decodeInteger(data, offset);

        return (integer, length);
    }

    function decodeTransactionHelper(
        bytes calldata transaction_
    ) public pure returns (bytes32, uint256, uint256, address) {
        (
            bytes32 covhash,
            uint256 value,
            uint256 denom,
            address recipient
        ) = _decodeTransaction(transaction_);

        return (
            covhash,
            value,
            denom,
            recipient
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

    function denomToStringHelper(uint256 denom) public pure returns (string memory) {
        if (denom == MEL) {
            return "MEL";
        } else if (denom == SYM) {
            return "SYM";
        } else if (denom == ERG) {
            return "ERG";
        } else {
            string memory txHash = abi.encodePacked(denom).toHexString();

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
        bytes32 stakesLeaf,
        uint256 blockHeight
    ) public {
        leafHeights[stakesLeaf] = blockHeight;
    }

    function verifyStakesHelper(uint256 blockHeight, bytes32 stakesHash) public {
        headers[blockHeight].stakesHash = stakesHash;
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

    function testBlake3DifferentialFFI(bytes calldata data) public {
        string[] memory cmds = new string[](4);

        cmds[0] = FFI_PATH;
        cmds[1] = 'blake3';
        cmds[2] = '--bytes';
        cmds[3] = data.toHexString();

        bytes memory result = vm.ffi(cmds);
        bytes32 rustHash = abi.decode(result, (bytes32));

        bytes32 solHash = _hashDatablock(data);

        assertEq(solHash, rustHash);
    }

    function testEd25519DifferentialFFI(bytes memory message) public {
        string[] memory cmds = new string[](4);

        cmds[0] = FFI_PATH;
        cmds[1] = 'ed25519';
        cmds[2] = '--bytes';
        cmds[3] = message.toHexString();

        bytes memory result = vm.ffi(cmds);

        (bytes32 signer, bytes32 r, bytes32 S) = abi.decode(result, (bytes32, bytes32, bytes32));

        assertTrue(Ed25519.verify(signer, r, S, message));
    }
}

// contract for tests involving internal functions that have calldata params
contract ThemelioBridgeTestInternalCalldataFFI is Test {
    using Strings for uint;
    using ByteStrings for bytes;

    uint256 constant MEL = 0;
    uint256 constant SYM = 1;

    ThemelioBridgeTestFFI bridgeTest;

    function setUp() public {
        bridgeTest = new ThemelioBridgeTestFFI();
    }

        /* =========== Differential Fuzz and FFI Tests =========== */

    function testBigHashFFI() public {
        string[] memory cmds = new string[](2);
        cmds[0] = FFI_PATH;
        cmds[1] = 'big-hash';

        bytes memory packedData = vm.ffi(cmds);
        (bytes memory data, bytes32 dataHash) = abi.decode(packedData, (bytes, bytes32));

        bytes32 bigHash = bridgeTest.hashDatablockHelper(data);

        assertEq(bigHash, dataHash);
    }

    function testDecodeHeaderDifferentialFFI(uint128 mod) public {
        string[] memory cmds = new string[](4);

        cmds[0] = FFI_PATH;
        cmds[1] = 'decode-header';
        cmds[2] = '--modifier';
        cmds[3] = uint256(mod).toString();

        bytes memory packedData = vm.ffi(cmds);
        (
            bytes memory header,
            uint256 blockHeight,
            bytes32 transactionsHash,
            bytes32 stakesHash
        ) = abi.decode(packedData, (bytes, uint256, bytes32, bytes32));

        (
            uint256 decodedBlockHeight,
            bytes32 decodedTransactionsHash,
            bytes32 decodedStakesHash
        ) = bridgeTest.decodeHeaderHelper(header);

        assertEq(decodedBlockHeight, blockHeight);
        assertEq(decodedTransactionsHash, transactionsHash);
        assertEq(decodedStakesHash, stakesHash);
    }

    function testDecodeIntegerDifferentialFFI(uint128 integer) public {
        string[] memory cmds = new string[](4);

        cmds[0] = FFI_PATH;
        cmds[1] = 'decode-integer';
        cmds[2] = '--integer';
        cmds[3] = uint256(integer).toString();

        bytes memory result = vm.ffi(cmds);

        (bytes memory resultsInteger, uint256 resultsIntegerSize) = abi.decode(result, (bytes, uint256));

        (uint256 decodedInteger, uint256 decodedIntegerSize) = bridgeTest.decodeIntegerHelper(resultsInteger, 0);

        assertEq(decodedInteger, integer);
        assertEq(decodedIntegerSize, resultsIntegerSize);
    }

    function testDecodeTransactionDifferentialFFI(
        bytes32 covhash,
        uint128 value,
        uint256 denom,
        address recipient
    ) public {
        string[] memory cmds = new string[](10);

        cmds[0] = FFI_PATH;
        cmds[1] = 'decode-transaction';
        cmds[2] = '--covhash';
        cmds[3] = abi.encodePacked(covhash).toHexString();
        cmds[4] = '--value';
        cmds[5] = uint256(value).toString();
        cmds[6] = '--denom';
        cmds[7] = bridgeTest.denomToStringHelper(denom);
        cmds[8] = '--recipient';
        cmds[9] = abi.encodePacked(recipient).toHexString();

        bytes memory transaction = vm.ffi(cmds);

        (
            bytes32 extractedCovhash,
            uint256 extractedValue,
            uint256 extractedDenom,
            address extractedRecipient
        ) = bridgeTest.decodeTransactionHelper(transaction);

        assertEq(extractedCovhash, covhash);
        assertEq(extractedValue, value);
        assertEq(extractedDenom, denom);
        assertEq(extractedRecipient, recipient);
    }

    function testVerifyHeaderDifferentialFFI(uint8 numStakeDocs) public {
        vm.assume(numStakeDocs > 0 && numStakeDocs < 50);

        string[] memory cmds = new string[](4);
        cmds[0] = FFI_PATH;
        cmds[1] = 'verify-header';
        cmds[2] = '--num-stakedocs';
        cmds[3] = uint256(numStakeDocs).toString();

        bytes memory data = vm.ffi(cmds);

        (
            bool enoughVotes,
            bytes memory header,
            uint256 stakesHeight,
            bytes memory stakesDatablock,
            bytes32[] memory signatures
        ) = abi.decode(data, (bool, bytes, uint256, bytes, bytes32[]));

        bytes32 stakesLeaf = keccak256(stakesDatablock);

        bridgeTest.verifyHeaderHelper(stakesLeaf, stakesHeight);

        bool success;
        uint256 rounds;
        uint256 signaturesLength = signatures.length / 2;
        while (!success) {
            if (!enoughVotes && signaturesLength <= rounds + VERIFICATION_LIMIT) {
                vm.expectRevert();

                success = bridgeTest.verifyHeader{gas: GAS_LIMIT}(
                    header,
                    stakesDatablock,
                    signatures,
                    VERIFICATION_LIMIT
                );

                break;
            }

            success = bridgeTest.verifyHeader{gas: GAS_LIMIT}(
                header,
                stakesDatablock,
                signatures,
                VERIFICATION_LIMIT
            );
            rounds += VERIFICATION_LIMIT;
        }

        assertTrue(success == enoughVotes);
    }

    function testVerifyHeaderCrossEpochDifferentialFFI(uint8 epoch) public {
        vm.assume(epoch > 0);

        string[] memory cmds = new string[](4);
        cmds[0] = FFI_PATH;
        cmds[1] = 'verify-header-cross-epoch';
        cmds[2] = '--epoch';
        cmds[3] = uint256(epoch).toString();

        bytes memory data = vm.ffi(cmds);

        (
            bool enoughVotes,
            bytes memory header,
            uint256 stakesHeight,
            bytes memory stakesDatablock,
            bytes32[] memory signatures
        ) = abi.decode(data, (bool, bytes, uint256, bytes, bytes32[]));

        bytes32 stakesLeaf = keccak256(stakesDatablock);

        bridgeTest.verifyHeaderHelper(stakesLeaf, stakesHeight);

        bool success;
        uint256 rounds;
        uint256 signaturesLength = signatures.length / 2;
        while (!success) {
            if (!enoughVotes && signaturesLength <= rounds + VERIFICATION_LIMIT) {
                emit log_uint(signaturesLength);
                emit log_uint(rounds);
                emit log_uint(VERIFICATION_LIMIT);
                vm.expectRevert();

                success = bridgeTest.verifyHeader{gas: GAS_LIMIT}(
                    header,
                    stakesDatablock,
                    signatures,
                    VERIFICATION_LIMIT
                );

                break;
            }

            success = bridgeTest.verifyHeader{gas: GAS_LIMIT}(
                header,
                stakesDatablock,
                signatures,
                VERIFICATION_LIMIT
            );
            rounds += VERIFICATION_LIMIT;
        }

        assertTrue(success == enoughVotes);
    }

    function testVerifyStakesDifferentialFFI(uint8 numStakeDocs) public {
        vm.assume(numStakeDocs > 0 && numStakeDocs < 66);

        string[] memory cmds = new string[](4);
        cmds[0] = FFI_PATH;
        cmds[1] = 'verify-stakes';
        cmds[2] = '--num-stakedocs';
        cmds[3] = uint256(numStakeDocs).toString();

        bytes memory data = vm.ffi(cmds);

        (
            bytes32 stakesHash,
            bytes memory stakesDatablock,
            uint256 stakesIndex,
            bytes32[] memory stakesProof
        ) = abi.decode(data, (bytes32, bytes, uint256, bytes32[]));

        uint256 blockHeight = 42;
        bridgeTest.verifyStakesHelper(blockHeight, stakesHash);

        bool verified = bridgeTest.verifyStakes{gas: GAS_LIMIT}(
            blockHeight,
            stakesDatablock,
            stakesIndex,
            stakesProof
        );

        assert(verified);
    }

    function testVerifyTxDifferentialFFI(uint8 numTransactions) public {
        vm.assume(numTransactions > 0);

        string[] memory cmds = new string[](4);
        cmds[0] = FFI_PATH;
        cmds[1] = 'verify-transaction';
        cmds[2] = '--num-transactions';
        cmds[3] = uint256(numTransactions).toString();

        bytes memory data = vm.ffi(cmds);

        (
            bytes32 transactionsHash,
            bytes memory transaction,
            uint256 txIndex,
            uint256 blockHeight,
            bytes32[] memory proof,
            uint256 denom,
            uint256 value,
            address recipient
        ) = abi.decode(
            data,
            (bytes32, bytes, uint256, uint256, bytes32[], uint256, uint256, address)
        );

        uint256 preBalance = bridgeTest.balanceOf(recipient, denom);

        bridgeTest.verifyTxHelper(blockHeight, transactionsHash, 0);
        bridgeTest.verifyTx(transaction, txIndex, blockHeight, proof);

        uint256 postBalance = bridgeTest.balanceOf(recipient, denom);

        assertEq(postBalance, preBalance + value);
    }
}