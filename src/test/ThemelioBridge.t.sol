// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.13;

import 'forge-std/Test.sol';
import 'openzeppelin-contracts/contracts/utils/Strings.sol';
import './utils/ByteStrings.sol';
import '../ThemelioBridge.sol';
import '../BridgeProxy.sol';
import '../IThemelioBridge.sol';

contract ThemelioBridgeTest is ThemelioBridge, Test {
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

    function decodeTransactionHelper(
        bytes calldata transactions_
    ) public pure returns (bytes32, uint256, uint256, address) {
        (
            bytes32 covhash,
            uint256 value,
            uint256 denom,
            address recipient
        ) = _decodeTransaction(transactions_);

        return (
            covhash,
            value,
            denom,
            recipient
        );
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

        /* =========== Unit Tests =========== */

    function testdecodeInteger() public {
        // 250 with no padding
        bytes memory integer1Bytes = abi.encodePacked(bytes1(0xfa));
        uint256 integer1 = 0xfa;
        uint256 integer1Length = 1;
        uint256 integer1Offset = 0;
        (
            uint256 decodedInteger1,
            uint256 decodedInteger1Length
        ) = _decodeInteger(integer1Bytes, integer1Offset);

        assertEq(decodedInteger1, integer1);
        assertEq(decodedInteger1Length, integer1Length);

        // 251 with 1 byte of padding on both sides
        bytes memory integer3Bytes = abi.encodePacked(bytes5(0xfffbfbfbff));
        uint256 integer3 = 0xfbfb;
        uint256 integer3Length = 3;
        uint256 integer3Offset = 1;
        (
            uint256 decodedInteger3,
            uint256 decodedInteger3Length
        ) = _decodeInteger(integer3Bytes, integer3Offset);

        assertEq(decodedInteger3, integer3);
        assertEq(decodedInteger3Length, integer3Length);

        // 2**16 with 2 bytes of padding on both sides
        bytes memory integer5Bytes = abi.encodePacked(bytes9(0xfffffcfcfcfcfcffff));
        uint256 integer5 = 0xfcfcfcfc;
        uint256 integer5Length = 5;
        uint256 integer5Offset = 2;
        (
            uint256 decodedInteger5,
            uint256 decodedInteger5Length
        ) = _decodeInteger(integer5Bytes, integer5Offset);

        assertEq(decodedInteger5, integer5);
        assertEq(decodedInteger5Length, integer5Length);

        // 2**32 with 3 bytes of padding on both sides
        bytes memory integer9Bytes = abi.encodePacked(bytes15(0xfffffffdfdfdfdfdfdfdfdfdffffff));
        uint256 integer9 = 0xfdfdfdfdfdfdfdfd;
        uint256 integer9Length = 9;
        uint256 integer9Offset = 3;
        (
            uint256 decodedInteger9,
            uint256 decodedInteger9Length
        ) = _decodeInteger(integer9Bytes, integer9Offset);

        assertEq(decodedInteger9, integer9);
        assertEq(decodedInteger9Length, integer9Length);

        // 2**64 with 4 bytes of padding on both sides
        bytes memory integer17Bytes = abi.encodePacked(
            bytes25(0xfffffffffefefefefefefefefefefefefefefefefeffffffff)
        );
        uint256 integer17 = 0xfefefefefefefefefefefefefefefefe;
        uint256 integer17Length = 17;
        uint256 integer17Offset = 4;
        (
            uint256 decodedInteger17,
            uint256 decodedInteger17Length
        ) = _decodeInteger(integer17Bytes, integer17Offset);

        assertEq(decodedInteger17, integer17);
        assertEq(decodedInteger17Length, integer17Length);
    }

    function testEd25519() public {
        bytes memory message = abi.encodePacked('The foundation of a trustless Internet');
        bytes32 signer = 0xd82042fffbb34d09630aa9c56a2c3f0f2be196f28aaea9cc7332b509c7fc69da;
        bytes32 r = 0x8854ac521549d8d45d1743d187d8da9ea15d7ece91d0024cac14ad344a0206e2;
        bytes32 S = 0x0101137835043d999fe08b6e946cf5f120a5eaa10681dfa698c963d4ba65220c;

        bool success = Ed25519.verify(signer, r, S, message);
        assertTrue(success);
    }

    function testHashNode() public {
        assertEq(
            _hashNodes(abi.encodePacked('node')),
            0x7b568d1038ae40d3683670f02841d47a11794b6a629c2c02fedd5856e868cc2b
        );
    }

    function testSlice() public {
        bytes memory data = abi.encodePacked(
            bytes8(0x0123456789abcdef)
        );
        uint256 start;
        uint256 end;
        bytes memory result;

        // start <= end, regular slice
        start = 2;
        end = 5;
        result = _slice(data, start, end);
        assertEq0(result, abi.encodePacked(bytes3(0x456789)));

        // start > end, reverse slice
        start = 7;
        end = 0;
        result = _slice(data, start, end);
        assertEq0(result, abi.encodePacked(bytes7(0xefcdab89674523)));
    }
}

// contract for tests involving internal functions that have calldata params
contract ThemelioBridgeTestInternalCalldata is Test {
    using Strings for uint;
    using ByteStrings for bytes;

    uint256 constant MEL = 0;
    uint256 constant SYM = 1;

    ThemelioBridgeTest bridgeTest;

    function setUp() public {
        bridgeTest = new ThemelioBridgeTest();
    }

            /* =========== Unit Tests =========== */

    // function testApproveAndBurn() public {
    //     address burner = msg.sender;
    //     uint256 id = MEL;
    //     uint256 startBalance = bridgeTest.balanceOf(burner, id);
    //     uint256 value = 666;
    //     bytes32 themelioRecipient;

    //     bridgeTest.mintHelper(burner, id, value);

    //     assertEq(bridgeTest.balanceOf(burner, id), startBalance + value);

    //     bridgeTest.setApprovalForAll(address(this), true);

    //     bridgeTest.burn(burner, id, value, themelioRecipient);
    //     // assert log is emitted

    //     uint256 finalBalance = bridgeTest.balanceOf(burner, id);

    //     assertEq(finalBalance, startBalance);
    // }

    function testBatchBurn() public {}

    function testComputeMerkleRoot() public {
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = 0xccaa1158058ab1de4168de28f6bee9f2fea080042a820802699755262c8f2e5f;
        proof[1] = 0x171668289941c5ef323e451b1fd651688ca3dd96a7b91fc83fd42bc3845d7b81;

        bytes32 txHash = 0x2e187bec885cacb89e4adc7f4dd4a658d2c924464367ee9bff8c10e0821409c5;
        uint256 txIndex = 3;

        bytes32 merkleRoot = bridgeTest.computeMerkleRootHelper(
            txHash,
            txIndex,
            proof
        );

        assertEq(merkleRoot, 0xfdb8082e4be32395b895e7e46719f70c9155f426db3d2e31ce7632dced994608);
    }

    function testDecodeStakeDoc() public {
        bytes memory encodedStakeDoc = abi.encodePacked(
            bytes32(0x5dc57fc274b1235e28352d67b8ee4a30b74b5d0b070dc4400f30714cda80b280),
            bytes32(0xfd5fdd4268ccf9ed06fd481be5231b037e8efe905ff5aae270ee660c7240fe32),
            bytes3(0x05b030)
        );

        (
            bytes32 publicKey,
            uint256 epochStart,
            uint256 epochPostEnd,
            uint256 symsStaked
        ) = bridgeTest.decodeStakeDocHelper(encodedStakeDoc);

        assertEq(publicKey, 0x5dc57fc274b1235e28352d67b8ee4a30b74b5d0b070dc4400f30714cda80b280);
        assertEq(epochStart, 499329790025850207);
        assertEq(epochPostEnd, 10267647615552527176);
        assertEq(symsStaked, 64716893496921337859207055163356700560);
    }

    function testDecodeTransaction() public {
        bytes memory transaction = abi.encodePacked(
            bytes32(0x51010a1a82a7f70497fbbb549a63b4f11fe2062fc8eb78908138d5ec6c4c37b4),
            bytes32(0xd46d960200000000000000000000000000000000000000000000000000000000),
            bytes32(0x00000000feea64accf835d2e8c75071bb47bc74bde016d14c505b3263fec82f8),
            bytes32(0xb624f4ba9c01b20e506b5e1e868010bfd9908ba0027dbb1f063b9ef1f20cae1f),
            bytes32(0x75e2ccc9596eac88253175b1fedd531bfa008451b726a8125afd34db9e016d00),
            bytes26(0xfe49707269c1dd7303bae99ab55ffd4db401017b02ddce010105)
        );

        (
            bytes32 covhash,
            uint256 value,
            uint256 denom,
            address recipient
        ) = bridgeTest.decodeTransactionHelper(transaction);

        assertEq(covhash, 0);
        assertEq(value, 295482083328956529783620102020496385258);
        assertTrue(denom == MEL);
        assertEq(recipient, 0xc505B3263fEc82F8b624f4BA9C01b20E506b5E1e);
    }

    function testHashDatablock() public {
        bytes32 dataHash = bridgeTest.hashDatablockHelper(abi.encodePacked('datablock'));

        assertEq(
            dataHash,
            0x6ccea12fef78d2af66a4bca268cdbeccc47b3ee3ec9fbf83da1a67b526e9da2e
        );
    }

    function testverifyHeader() public {
        uint256 verifierHeight = 0x183fbb57d5fe52;
        bytes32 verifierStakesHash =
            0x52bf0665451a2df0c62e7b57faf3fa93eeebd00a595ec124fd187790dac4278d;
        bytes memory header = abi.encodePacked(
            bytes32(0xff8d5e99a13192a02d28fd80d3bf4e607d9bb232cbe681868d6bcbbd2058b86f),
            bytes32(0x10fd53fed557bb3f18007200ba6d4739bfd685ce253c94530b3c8aa309a8ed1e),
            bytes32(0xe12d2326c6acd39f86031580059da0045acf505fec7d15ddf3f3eb30b66cc6f2),
            bytes32(0x165323d1aa82d35248aa7d6ab6d2d69d0ee38160b317063a231bbc239611a563),
            bytes32(0x3197f8715d07882b82a3feb60bebef9444aafd4a39b714eeac1f5afe97adc6be),
            bytes32(0xca073cd05eb3ad48a00663d2fea825ca078019191a436fa10ef129a4502b710c),
            bytes32(0x3eccc3aeb2b86647da1cf1599cca4fdd9d1deb7e1b5b1da2986fa3cda412ac2d),
            bytes29(0x7176a115d25f40e9fc66338d970a37ee37c835cfaac452931c7182391f)
        );
        bytes memory stakeDocs = abi.encodePacked(
            bytes32(0xfc75460291714ea3c5dd8ddc0eaccd185fa5939c4607c9ab7f03c05e756e4e91),
            bytes24(0x9e15793eb2fc5504783dfd39c418915273fa44fc75460291)
        );
        bytes32[] memory signatures = new bytes32[](2);
        signatures[0] = 0xbfab48aab1c659429e15b4be7fe49f4e671b224133be228c1c76ca75a03f2d47;
        signatures[1] = 0x7cd99162097711e409526ec81dd2ab6ee1b56cf855da7355c365a142cf86b50b;

        bridgeTest.verifyHeaderHelper(verifierStakesHash, verifierHeight);

        bool success = bridgeTest.verifyHeader(
            verifierHeight,
            header,
            stakeDocs,
            signatures,
            true
        );

        assertTrue(success);
    }

    function testVerifyHeaderMultiStake() public {
        uint256 verifierHeight = 0x10b748b2f980a8;
        bytes32 verifierStakesHash =
            0xd0dc52accc736b78b7e97f44199a7d2e13024f97cd307592e4e0c1806f18f419;
        bytes memory header = abi.encodePacked(
            bytes32(0xffa5ca33cac8a871c126d6ea90817f61b3fe6dd8f989279fd2b722adcf9aa928),
            bytes32(0x4bfda980f9b248b71000cc29cb82a4ce59d145edc182cc1487b4625a7731e8d0),
            bytes32(0x085590a13e13f63a54573685ae577e5074cc9fc5c27f48437dba33ed1bb80516),
            bytes32(0xc5de0ce4d2825a2f9bf51b3db745c2aea7e82e8e6cdb64af80028e726a1b5d60),
            bytes32(0x4edf6834f9d4ddf8085bfe09d7b23bd7ea2a323d48c3f3a2b87f1cfeaaa9d312),
            bytes32(0x687b1ef6b7632cdcf93fcaf4fe8b7ed3e41dd54df3272765c4bc0939bc734819),
            bytes32(0x017a69884bdec1865a595b8fd861c9b0775fd5f67d786987efe1081d441e2802),
            bytes29(0x9dc372cc3c1bc96439c6d67286c8f66c63a81121a3dec7e64bad8550fd)
        );
        bytes memory stakeDocs = abi.encodePacked(
            bytes32(0xfc724fb1579e572480f4b8e7832dccaab7d6ba5d50cf41b112e3c4c2e33cf9d4),
            bytes32(0x82f3c38b80fc619fd053fd5919c909ec06c89dfcdc06bc316fbdb2f38cd7a46f),
            bytes32(0xeb94920535bbd928c672227a6c2222a97277c0609c1a6141fc5a4cec34fdc43c),
            bytes11(0xae4dc12a184dfc9648f525)
        );
        bytes32[] memory signatures = new bytes32[](4);
        signatures[0] = 0x5b8d4eb42a989be6ab99a89f2568c698051e149505849948299ba5034e2468f9;
        signatures[1] = 0x46d6d6dceabe0c8973d63eea075b395171d05d39e7f21bd7f8d2448e03ecb001;
        signatures[2] = 0xc82e64734286625395420544394730c911c6a5a41ab8b189b60b21d58e1e9b0c;
        signatures[3] = 0x14062b1bd5bd7edd00c1271d24bcff275ff355e1111cb7306de87251bf8e5f03;

        bridgeTest.verifyHeaderHelper(verifierStakesHash, verifierHeight);

        bool success = bridgeTest.verifyHeader(
            verifierHeight,
            header,
            stakeDocs,
            signatures,
            true
        );

        assertTrue(success);
    }

    function testVerifyHeadersMultiTx() public {
        // reduce tx gas
        // first tx
        // second tx
        // assert header was verified
    }

    // function testCannotVerifyHeader() public {
    //     bytes memory header = abi.encodePacked(
    //         bytes32(0xffa011c4104d79413ef82b91c5dc1d93991b144d0a5c388f56c49997cb90fe61),
    //         bytes32(0xdcfd90cade26f7d43c1dae753f62c43a2e9e8980092d74b176d44e66934e7d4f),
    //         bytes32(0x695dab16ad3709ab4ddd18e38c16fef2b41f08ca978f073fd284dc4afb38847c),
    //         bytes32(0xb429c88ca67f20e2fceac8fc42d07e3c70edb34d2580a56577e7efba232ec576),
    //         bytes32(0x53d9589ea14aeaf0a538fee973f4378fbe51d158637bed4a909ee8fe44a095b0),
    //         bytes32(0x9d5fb644423e6805bded708afe9ecbc17767c13584eb68a2f813ddfd3b099c23),
    //         bytes32(0x89c2290dd6def728f395ce85c4067636d33c2b4708872728f8308508331b73c0),
    //         bytes29(0xcee7078be495c4144b8d486a34ec81fc893d515a79ed2b1b860b381f63)
    //     );

    //     bytes32[] memory signersSubmitStakers = new bytes32[](3);
    //     // 30 syms staked
    //     signersSubmitStakers[0] = 0x2eb2115fe909017c0dcff17846dba5da36ccc56ddf01506a1ebca94ab0f65bc9;
    //     // 31 syms staked
    //     signersSubmitStakers[1] = 0x419b43ad463c65f7ef872bb2eb3aa6ac5fd094351703dfed73656627b3bcdd7d;
    //     // 32 syms staked
    //     signersSubmitStakers[2] = 0x00083c8fe73cfdb00f1c3f8998aeb87f9d2534d6ee21fc442b4fe40eba03e39e;

    //     // we are only including signatures for the first 2 signers so staked syms of signers < 2/3
    //     bytes32[] memory signatures = new bytes32[](4);
    //     signatures[0] = 0xab10f3f8e8fd7987b903bee83c4d935db6e41c8cdb0149e81569b50f737fe79f;
    //     signatures[1] = 0x77f8fb24f0ebdaa0634b79358a5d576c36897eea06985a38af811e930c702702;
    //     signatures[2] = 0xd5e16061798104ca5fd82587fd499239df5f72d7a76dbabce4b0fcc90b297957;
    //     signatures[3] = 0x0fa9456df1c04d95286cd3b1cf25ba0676670171c22e5085f6346a13f2f3ae0a;

    //     // this call saves the staker information in the appropriate epoch for this test
    //     bridgeTest.submitHeaderTestHelper(signersSubmitStakers);

    //     // declaring a new signers array so the size is correct in relation to the signatures array
    //     bytes32[] memory signersSubmitHeader = new bytes32[](2);
    //     // 30 syms staked
    //     signersSubmitHeader[0] = 0x2eb2115fe909017c0dcff17846dba5da36ccc56ddf01506a1ebca94ab0f65bc9;
    //     // 31 syms staked
    //     signersSubmitHeader[1] = 0x419b43ad463c65f7ef872bb2eb3aa6ac5fd094351703dfed73656627b3bcdd7d;

    //     // expect a revert due to insufficient signatures
    //     vm.expectRevert(
    //         abi.encodeWithSelector(
    //             ThemelioBridge.InsufficientSignatures.selector,
    //             61,
    //             93
    //         )
    //     );

    //     bridgeTest.submitHeader(header, signersSubmitHeader, signatures);
    // }

    function testVerifyStakes() public pure {}

    // function testVerifyTx() public {
    //     uint256 blockHeight = 11699990686140247438;
    //     bytes32 transactionsHash =
    //         0x580997689374a72c83aaa25fd2517e1e60c17034413d513e090435941fb318ce;
    //     bytes32 stakesHash =
    //         0xf7490fc7be550aefa27eb01a33d51138deda54823601f2f87283ce88f04a5831;

    //     bytes memory transaction = // needs to be recreated and signed; make sure covhash = 0;
    //     uint256 txIndex = 3;

    //     bytes32[] memory proof = new bytes32[](2);
    //     proof[0] = 0x1a2582eb25c727ff0d4fe22c9d921e2b6186b6160a2c72f0fb8cb2e5f126bfb1;
    //     proof[1] = 0xf12599cbd9d49c0aad7aa00257dd4a1dd2b1a41b7b71cebc7a8217a121586339;

    //     uint256 value = 153168801660958298760728062610398288911;
    //     address recipient = 0x762346cea1cb891dbC4b30d328598F4c9568227d;

    //     bridgeTest.verifyTxHelper(blockHeight, transactionsHash, stakesHash);

    //     bool success = bridgeTest.verifyTx(transaction, txIndex, blockHeight, proof);
    //     assertTrue(success);

    //     uint256 recipientBalance = bridgeTest.balanceOf(recipient, MEL);
    //     assertEq(recipientBalance, value);
    // }

    // function testCannotVerifyTxTwice() public {
    //     uint256 blockHeight = 11699990686140247438;
    //     bytes32 transactionsHash =
    //         0x580997689374a72c83aaa25fd2517e1e60c17034413d513e090435941fb318ce;
    //     bytes32 stakesHash =
    //         0xf7490fc7be550aefa27eb01a33d51138deda54823601f2f87283ce88f04a5831;

    //     bytes memory transaction = abi.encodePacked(
    //         bytes32(0x5101ac47ce6d06e6b937043484412f7f8ecffc5227284f81e5d5d093d5c4c57d),
    //         bytes32(0x0ba7120200000000000000000000000000000000000000000000000000000000),
    //         bytes32(0x00000000fe0f9c28281dfe5cca35b0647af83c3b73016d14762346cea1cb891d),
    //         bytes32(0xbc4b30d328598f4c9568227de69e61600cd3347a796664f34e4cb1e0b31f453b),
    //         bytes32(0xb8fa84e20ac43b36074a4394feb61cd4ef5a811fd2f8144b8b3f3a8a10016d00),
    //         bytes26(0xfe113c98493ad256720c5f8cfb32000af301018c028a8101018f)
    //     );
    //     uint256 txIndex = 3;

    //     bytes32[] memory proof = new bytes32[](2);
    //     proof[0] = 0x1a2582eb25c727ff0d4fe22c9d921e2b6186b6160a2c72f0fb8cb2e5f126bfb1;
    //     proof[1] = 0xf12599cbd9d49c0aad7aa00257dd4a1dd2b1a41b7b71cebc7a8217a121586339;

    //     uint256 value = 153168801660958298760728062610398288911;
    //     address recipient = 0x762346cea1cb891dbC4b30d328598F4c9568227d;

    //     bridgeTest.verifyTxHelper(blockHeight, transactionsHash, stakesHash);

    //     bool success = bridgeTest.verifyTx(transaction, txIndex, blockHeight, proof);
    //     assertTrue(success);

    //     uint256 recipientBalance = bridgeTest.balanceOf(recipient, MEL);
    //     assertEq(recipientBalance, value);

    //     // expect a revert due to already verified tx
    //     vm.expectRevert(
    //         abi.encodeWithSelector(
    //             ThemelioBridge.TxAlreadyVerified.selector,
    //             0xd0deea06e5ab0f53bd4e7c64ec733c815ab200a70d11db3dcb55553343157b7f
    //         )
    //     );

    //     bridgeTest.verifyTx(transaction, txIndex, blockHeight, proof);
    // }

    function testDeploy() public {
        ThemelioBridge implementation = new ThemelioBridge();

        address _logic = address(implementation);
        bytes memory _data = abi.encode(
            bytes4(keccak256('initialize(uint256,bytes32,bytes32)')),
            0,
            0,
            0
        );

        BridgeProxy proxy = new BridgeProxy(_logic, _data);

        string memory uri = IThemelioBridge(address(proxy)).uri(0);

        assertEq(uri, 'https://melscan.themelio.org/{id}.json');
    }
}