// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.10;

import 'ds-test/test.sol';
import '../ThemelioBridge.sol';

uint256 constant EPOCH_LENGTH = 200_000;

contract ThemelioBridgeTest is ThemelioBridge, DSTest {
    function testDecimals() public {
        uint256 decimals = decimals();

        assertEq(decimals, 9);
    }

    function testEd25519() public {
        bytes memory message = abi.encodePacked("The foundation of a trustless Internet");
        bytes32 publicKey = 0xd82042fffbb34d09630aa9c56a2c3f0f2be196f28aaea9cc7332b509c7fc69da;
        bytes32 r = 0x8854ac521549d8d45d1743d187d8da9ea15d7ece91d0024cac14ad344a0206e2;
        bytes32 S = 0x0101137835043d999fe08b6e946cf5f120a5eaa10681dfa698c963d4ba65220c;

        bool success = Ed25519.verify(publicKey, r, S, message);
        assertTrue(success);
    }

    function testBlake3Hasher() public {
        Hasher memory hasher = blake3.new_hasher();
        hasher = blake3.update_hasher(hasher, unicode'hellohello?');
        bytes memory output = blake3.finalize(hasher);

        assertEq(
            bytes32(output),
            0x10e6acb2cfcc4bb07588ad5b8e85f6a13f19e24f3302826effd93ce1ebbece6e
        );
    }

    function testBlake3KeyedHasher() public {
        Hasher memory hasher = blake3.new_keyed(unicode'hellohello!');
        hasher = blake3.update_hasher(hasher, unicode'hellohello?');
        bytes memory output = blake3.finalize(hasher);

        assertEq(
            bytes32(output),
            0x0edd7e645d2bc1bba1f323f6339a3d0448ec6b675991e8dc76d2396eb0dffca2
        );
    }

    function testHashDatablock() public {
        assertEq(
            _hashDatablock(abi.encodePacked('datablock')),
            0x6ccea12fef78d2af66a4bca268cdbeccc47b3ee3ec9fbf83da1a67b526e9da2e
        );
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

    function decodeIntegerTestHelper(
        bytes calldata header,
        uint256 offset
    ) public pure returns (uint256) {
        uint256 integer = _decodeInteger(header, offset);

        return integer;
    }

    function testEncodedIntegerSize() public {
        // 250 with no padding
        bytes memory oneByteInteger = abi.encodePacked(bytes1(0xfa));
        uint256 oneByteSize = _encodedIntegerSize(oneByteInteger, 0);
        assertEq(oneByteSize, 1);

        // 251 with 1 byte of padding on both sides
        bytes memory threeByteInteger = abi.encodePacked(bytes5(0xfffbfb00ff));
        uint256 threeByteSize = _encodedIntegerSize(threeByteInteger, 1);
        assertEq(threeByteSize, 3);

        // 2**16 with 2 bytes of padding on both sides
        bytes memory fiveByteInteger = abi.encodePacked(bytes9(0xfffffc00000100ffff));
                uint256 fiveByteSize = _encodedIntegerSize(fiveByteInteger, 2);
        assertEq(fiveByteSize, 5);

        // 2**32 with 3 bytes of padding on both sides
        bytes memory nineByteInteger = abi.encodePacked(bytes15(0xfffffffd0000000001000000ffffff));
        uint256 nineByteSize = _encodedIntegerSize(nineByteInteger, 3);
        assertEq(nineByteSize, 9);

        // 2**64 with 4 bytes of padding on both sides
        bytes memory seventeenByteInteger = abi.encodePacked(
            bytes25(0xfffffffffe00000000000000000100000000000000ffffffff)
        );
        uint256 seventeenByteSize = _encodedIntegerSize(seventeenByteInteger, 4);
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
        bytes32 merkleRoot = _extractMerkleRoot(header);

        assertEq(
            merkleRoot,
            bytes32(0xcc31bac5a1ce87db5f32c719f5209984d6aea25829810b153d97ddb22b004f9e)
        );
    }

    function extractBlockHeightTestHelper(bytes calldata header) public pure returns (uint256) {
        uint256 blockHeight = _extractBlockHeight(header);

        return blockHeight;
    }

    function extractValueAndRecipientTestHelper(
        bytes calldata transaction
    ) public pure returns (uint256, address) {
        (uint256 value, address recipient) = _extractValueAndRecipient(transaction);

        return (value, recipient);
    }

    function testExtractTokenType() public {}

    function relayStakersHelper(
        uint256 epoch,
        bytes32 staker
    ) public view returns (uint256, uint256) {
        uint256 totalStakedSyms = epochs[epoch].totalStakedSyms;
        uint256 stakedSyms = epochs[epoch].stakers[staker];

        return (totalStakedSyms, stakedSyms);
    }

    function relayHeaderTestHelper(
        bytes32[] calldata signers
    ) public {
        uint256 blockHeight = 2106792883676695184;
        uint256 epoch = blockHeight / EPOCH_LENGTH;
        uint256 signersLength = signers.length;
        uint256 totalSyms = 0;

        for (uint256 i = 0; i < signersLength; ++i) {
            epochs[epoch].stakers[signers[i]] = i + 30;
            totalSyms += i + 30;
        }

        epochs[epoch].totalStakedSyms = totalSyms;
    }

    function computeMerkleRootTestHelper(
        bytes calldata header,
        uint256 blockHeight,
        bytes32 txHash,
        uint256 index,
        bytes32[] calldata proof
    ) public returns (bytes32) {
        headers[blockHeight] = header;

        bytes32 merkleRoot = _computeMerkleRoot(txHash, index, proof);

        return merkleRoot;
    }

    function verifyTxTestHelper(bytes calldata header, uint256 blockHeight) public {
        headers[blockHeight] = header;
    }
}

contract ThemelioBridgeTestInternalCalldata is DSTest {
    ThemelioBridgeTest bridgeTest;

    function setUp() public {
        bridgeTest = new ThemelioBridgeTest();
    }

    function testDecodeInteger() public {
        bytes memory header0 = abi.encodePacked(
            bytes1(0xfa)
        );
        uint256 integer0 = bridgeTest.decodeIntegerTestHelper(header0, 0);
        uint256 int0 = 0xfa;
        assertEq(integer0, int0);

        bytes memory header1 = abi.encodePacked(
            bytes4(0x00fb1111)
        );
        uint256 integer1 = bridgeTest.decodeIntegerTestHelper(header1, 1);
        uint256 int1 = 0x1111;
        assertEq(integer1, int1);

        bytes memory header2 = abi.encodePacked(
            bytes7(0x0000fc22222222)
        );
        uint256 integer2 = bridgeTest.decodeIntegerTestHelper(header2, 2);
        uint256 int2 = 0x22222222;
        assertEq(integer2, int2);

        bytes memory header3 = abi.encodePacked(
            bytes12(0x000000fd3333333333333333)
        );
        uint256 integer3 = bridgeTest.decodeIntegerTestHelper(header3, 3);
        uint256 int3 = 0x3333333333333333;
        assertEq(integer3, int3);

        bytes memory header4 = abi.encodePacked(
            bytes21(0x00000000fe44444444444444444444444444444444)
        );
        uint256 integer4 = bridgeTest.decodeIntegerTestHelper(header4, 4);
        uint256 int4 = 0x44444444444444444444444444444444;
        assertEq(integer4, int4);
    }

    function testExtractBlockHeight() public {
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
        uint256 blockHeight = bridgeTest.extractBlockHeightTestHelper(header);

        assertEq(blockHeight, 14217254977967302745);
    }

    function testExtractValueAndRecipient() public {
        bytes memory transaction = abi.encodePacked(
            bytes32(0x51010a1a82a7f70497fbbb549a63b4f11fe2062fc8eb78908138d5ec6c4c37b4),
            bytes32(0xd46d9602918b542ba2682549c3e246dc41ea843d3f7c565a45f4ee4529e314e6),
            bytes32(0xf4ababe4feea64accf835d2e8c75071bb47bc74bde016d14c505b3263fec82f8),
            bytes32(0xb624f4ba9c01b20e506b5e1e868010bfd9908ba0027dbb1f063b9ef1f20cae1f),
            bytes32(0x75e2ccc9596eac88253175b1fedd531bfa008451b726a8125afd34db9e016d00),
            bytes26(0xfe49707269c1dd7303bae99ab55ffd4db401017b02ddce010105)
        );

        (uint256 value, address recipient) =
            bridgeTest.extractValueAndRecipientTestHelper(transaction);

        assertEq(value, 295482083328956529783620102020496385258);
        assertEq(recipient, 0xc505B3263fEc82F8b624f4BA9C01b20E506b5E1e);
    }

    function testRelayStakers() public {
        uint256 height = 5496244452461458740;
        uint256 epoch = height / EPOCH_LENGTH;

        bytes32[] memory stakers = new bytes32[](1);
        stakers[0] = 0x7978bba95d52660fcf0e53382459df76a8d291c88f91530de234a479ec76c853;

        uint256[] memory stakerSyms = new uint256[](1);
        stakerSyms[0] = 0x316;

        bridgeTest.relayStakers(epoch, stakers, stakerSyms);

        (uint256 totalStakedSyms, uint256 stakerSymsResult) =
            bridgeTest.relayStakersHelper(epoch, stakers[0]);

        assertEq(stakerSymsResult, stakerSyms[0]);
        assertEq(totalStakedSyms, 0x316);
    }

    function testRelayHeader() public {
        bytes memory header = abi.encodePacked(
            bytes32(0xffa011c4104d79413ef82b91c5dc1d93991b144d0a5c388f56c49997cb90fe61),
            bytes32(0xdcfd90cade26f7d43c1dae753f62c43a2e9e8980092d74b176d44e66934e7d4f),
            bytes32(0x695dab16ad3709ab4ddd18e38c16fef2b41f08ca978f073fd284dc4afb38847c),
            bytes32(0xb429c88ca67f20e2fceac8fc42d07e3c70edb34d2580a56577e7efba232ec576),
            bytes32(0x53d9589ea14aeaf0a538fee973f4378fbe51d158637bed4a909ee8fe44a095b0),
            bytes32(0x9d5fb644423e6805bded708afe9ecbc17767c13584eb68a2f813ddfd3b099c23),
            bytes32(0x89c2290dd6def728f395ce85c4067636d33c2b4708872728f8308508331b73c0),
            bytes29(0xcee7078be495c4144b8d486a34ec81fc893d515a79ed2b1b860b381f63)
        );

        bytes32[] memory signers = new bytes32[](3);
        signers[0] = 0x2eb2115fe909017c0dcff17846dba5da36ccc56ddf01506a1ebca94ab0f65bc9;
        signers[1] = 0x419b43ad463c65f7ef872bb2eb3aa6ac5fd094351703dfed73656627b3bcdd7d;
        signers[2] = 0x00083c8fe73cfdb00f1c3f8998aeb87f9d2534d6ee21fc442b4fe40eba03e39e;

        bytes32[] memory signatures = new bytes32[](6);
        signatures[0] = 0xab10f3f8e8fd7987b903bee83c4d935db6e41c8cdb0149e81569b50f737fe79f;
        signatures[1] = 0x77f8fb24f0ebdaa0634b79358a5d576c36897eea06985a38af811e930c702702;
        signatures[2] = 0xd5e16061798104ca5fd82587fd499239df5f72d7a76dbabce4b0fcc90b297957;
        signatures[3] = 0x0fa9456df1c04d95286cd3b1cf25ba0676670171c22e5085f6346a13f2f3ae0a;
        signatures[4] = 0xc2a3f158b19db3c9e6be2e01578af8e49c6ce9bf158177efb2c18b558b853f40;
        signatures[5] = 0xd9d2aad475adf60bcf454130a1612f6128364c9d66ad7fe5eea5ca3522e16c01;

        bridgeTest.relayHeaderTestHelper(signers);

        bool success = bridgeTest.relayHeader(header, signers, signatures);
        assertTrue(success);
    }

    function testFailRelayHeader() public {
        bytes memory header = abi.encodePacked(
            bytes32(0xffa011c4104d79413ef82b91c5dc1d93991b144d0a5c388f56c49997cb90fe61),
            bytes32(0xdcfd90cade26f7d43c1dae753f62c43a2e9e8980092d74b176d44e66934e7d4f),
            bytes32(0x695dab16ad3709ab4ddd18e38c16fef2b41f08ca978f073fd284dc4afb38847c),
            bytes32(0xb429c88ca67f20e2fceac8fc42d07e3c70edb34d2580a56577e7efba232ec576),
            bytes32(0x53d9589ea14aeaf0a538fee973f4378fbe51d158637bed4a909ee8fe44a095b0),
            bytes32(0x9d5fb644423e6805bded708afe9ecbc17767c13584eb68a2f813ddfd3b099c23),
            bytes32(0x89c2290dd6def728f395ce85c4067636d33c2b4708872728f8308508331b73c0),
            bytes29(0xcee7078be495c4144b8d486a34ec81fc893d515a79ed2b1b860b381f63)
        );

        bytes32[] memory signers = new bytes32[](3);
        // 30 syms staked
        signers[0] = 0x2eb2115fe909017c0dcff17846dba5da36ccc56ddf01506a1ebca94ab0f65bc9;
        // 31 syms staked
        signers[1] = 0x419b43ad463c65f7ef872bb2eb3aa6ac5fd094351703dfed73656627b3bcdd7d;
        // 32 syms staked
        signers[2] = 0x00083c8fe73cfdb00f1c3f8998aeb87f9d2534d6ee21fc442b4fe40eba03e39e;

        // we are only including signatures for the first 2 signers so staked syms of signers < 2/3
        bytes32[] memory signatures = new bytes32[](4);
        signatures[0] = 0xab10f3f8e8fd7987b903bee83c4d935db6e41c8cdb0149e81569b50f737fe79f;
        signatures[1] = 0x77f8fb24f0ebdaa0634b79358a5d576c36897eea06985a38af811e930c702702;
        signatures[2] = 0xd5e16061798104ca5fd82587fd499239df5f72d7a76dbabce4b0fcc90b297957;
        signatures[3] = 0x0fa9456df1c04d95286cd3b1cf25ba0676670171c22e5085f6346a13f2f3ae0a;

        bridgeTest.relayHeaderTestHelper(signers);

        delete signers[2]; // removing the last signer so array is properly structured

        bool success = bridgeTest.relayHeader(header, signers, signatures);
        assertTrue(success);
    }

    function testComputeMerkleRoot() public {
        bytes memory header = abi.encodePacked(
            bytes32(0xff2bbcc7ff1abcfec545aff7a589bd42867bb3a140aa716d12c3ca63b7dedc11),
            bytes32(0xc2fd1a3df90305376ba000c9929046ab8241dfb934db78cb027b8914c8b3d499),
            bytes32(0xa3266b103df42c8d85c2b597181f1dc6c3f094374d246e72ac66e8ca13ce477e),
            bytes32(0x501e9bc498f42cbb4f6afdb8082e4be32395b895e7e46719f70c9155f426db3d),
            bytes32(0x2e31ce7632dced994608fe3c4577278cccc4770cf58ee02fb8f947fe31f77d52),
            bytes32(0xb6e4ff64e731af1a9048e729fe0f3f683400605e01b2f6de906878c70f42176e),
            bytes32(0x8b058b6f4cac123f02aa98e8ec90340faed8b7a04343f59b5b704d6c8adbf62f),
            bytes29(0xe448d0139b52c6ee9ea69067f83530e9a6285644f75f38767a2b0ab765)
        );
        uint256 blockHeight = 11559393363257539866;

        bytes32[] memory proof = new bytes32[](2);
        proof[0] = 0xccaa1158058ab1de4168de28f6bee9f2fea080042a820802699755262c8f2e5f;
        proof[1] = 0x171668289941c5ef323e451b1fd651688ca3dd96a7b91fc83fd42bc3845d7b81;

        bytes32 txHash = 0x2e187bec885cacb89e4adc7f4dd4a658d2c924464367ee9bff8c10e0821409c5;
        uint256 txIndex = 3;

        bytes32 merkleRoot = bridgeTest.computeMerkleRootTestHelper(
            header,
            blockHeight,
            txHash,
            txIndex,
            proof
        );

        assertEq(merkleRoot, 0xfdb8082e4be32395b895e7e46719f70c9155f426db3d2e31ce7632dced994608);
    }

    function testVerifyTx() public {
        bytes memory header = abi.encodePacked(
            bytes32(0xffa1b613c71ca1f47c6a45545d890cba063880070509cf4541f02e22e3b28ddc),
            bytes32(0x8cfd8eadc4328ab75ea2ea46ded74db70b4f05a3612857293f309efc84530d8e),
            bytes32(0x78d6cf8dabc39fdc3894b4cea0b16e0f68ac0ed5879663b3a48e6a1147e52c98),
            bytes32(0x6f584d94ade7ed7e589c580997689374a72c83aaa25fd2517e1e60c17034413d),
            bytes32(0x513e090435941fb318cefe8bfccde8afa6e9647f90002c43c6f357fe4b634e35),
            bytes32(0xb09f97f57be427435337f529fe05bc948f2af0adb2deb26e4bc2efe9b4cbe98b),
            bytes32(0x3c9b3bdd656aab25f358cad06af43a4802d474341db980c9d9d6c81ab4f7490f),
            bytes29(0xc7be550aefa27eb01a33d51138deda54823601f2f87283ce88f04a5831)
        );
        uint256 blockHeight = 11699990686140247438;

        bytes memory transaction = abi.encodePacked(
            bytes32(0x5101ac47ce6d06e6b937043484412f7f8ecffc5227284f81e5d5d093d5c4c57d),
            bytes32(0x0ba71202766a5980aa7d6c7c05294d217eb09872ea8579fbb4e7ed129fa2140f),
            bytes32(0xee549cc9fe0f9c28281dfe5cca35b0647af83c3b73016d14762346cea1cb891d),
            bytes32(0xbc4b30d328598f4c9568227de69e61600cd3347a796664f34e4cb1e0b31f453b),
            bytes32(0xb8fa84e20ac43b36074a4394feb61cd4ef5a811fd2f8144b8b3f3a8a10016d00),
            bytes26(0xfe113c98493ad256720c5f8cfb32000af301018c028a8101018f)
        );
        uint256 txIndex = 3;

        bytes32[] memory proof = new bytes32[](2);
        proof[0] = 0x1a2582eb25c727ff0d4fe22c9d921e2b6186b6160a2c72f0fb8cb2e5f126bfb1;
        proof[1] = 0xf12599cbd9d49c0aad7aa00257dd4a1dd2b1a41b7b71cebc7a8217a121586339;

        uint256 value = 153168801660958298760728062610398288911;
        address recipient = 0x762346cea1cb891dbC4b30d328598F4c9568227d;

        bridgeTest.verifyTxTestHelper(header, blockHeight);

        bool success = bridgeTest.verifyTx(transaction, txIndex, blockHeight, proof);
        assertTrue(success);

        uint256 recipientBalance = bridgeTest.balanceOf(recipient);
        assertEq(recipientBalance, value);
    }
}
