// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.13;

import 'forge-std/Test.sol';
import 'openzeppelin-contracts/contracts/utils/Strings.sol';
import './utils/ByteStrings.sol';
import '../ThemelioBridge.sol';
import '../ThemelioBridgeProxy.sol';
import '../IThemelioBridge.sol';

uint256 constant GAS_LIMIT = 25_000_000;
uint256 constant VERIFICATION_LIMIT = 100;

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

    function decodeStakeDocHelper(bytes calldata encodedStakeDoc_, uint256 offset)
        public pure returns (bytes32, uint256, uint256, uint256, uint256) {
        StakeDoc memory stakeDoc;
        (stakeDoc, offset) = _decodeStakeDoc(encodedStakeDoc_, offset);

        return (
            stakeDoc.publicKey,
            stakeDoc.epochStart,
            stakeDoc.epochPostEnd,
            stakeDoc.symsStaked,
            offset
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

    function decodeIntegerHelper(
        bytes calldata data,
        uint256 offset
    ) public pure returns (uint256, uint256) {
        (uint256 integer, uint256 length) = _decodeInteger(data, offset);

        return (integer, length);
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

    function verifyStakesHelper(bytes32 keccakStakesHash, bytes32 blake3StakesHash) public {
        stakesHashes[keccakStakesHash] = blake3StakesHash;
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
}

// contract for tests involving internal functions that have calldata params
contract ThemelioBridgeTestInternalCalldata is Test {
    using Strings for uint;
    using ByteStrings for bytes;

    uint256 constant MEL = 0;
    uint256 constant SYM = 1;

    ThemelioBridgeTest bridgeTest;

    event TokensBurned(
        bytes32 indexed themelioRecipient
    );

    function setUp() public {
        bridgeTest = new ThemelioBridgeTest();
    }

            /* =========== Unit Tests =========== */

    // function testBurn() public {
    //     address burner = address(42);
    //     uint256 id = MEL;
    //     uint256 startBalance = bridgeTest.balanceOf(burner, id);
    //     uint256 value = 666;
    //     bytes32 themelioRecipient;

    //     bridgeTest.mintHelper(burner, id, value);

    //     assertEq(bridgeTest.balanceOf(burner, id), startBalance + value);

    //     vm.prank(burner);
    //     bridgeTest.burn(burner, id, value, themelioRecipient);



    //     uint256 finalBalance = bridgeTest.balanceOf(burner, id);

    //     assertEq(finalBalance, startBalance);
    // }

    // function testBatchBurn() public {
    //     address burner = address(42);
    //     uint256 value1 = 0x74e3e110;
    //     uint256 value2 = 17;
    //     bytes32 themelioRecipient = 
    //         0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B000000000000000000000000;

    //     bridgeTest.mintHelper(burner, MEL, value1);
    //     bridgeTest.mintHelper(burner, SYM, value2);

    //     uint256[] memory ids = new uint256[](2);
    //     ids[0] = MEL;
    //     ids[1] = SYM;

    //     uint256[] memory values = new uint256[](2);
    //     ids[0] = value1;
    //     ids[1] = value2;

    //     vm.expectEmit(true, true, false, false);
    //     emit TokensBurned(themelioRecipient);

    //     vm.prank(burner);
    //     bridgeTest.burnBatch(burner, ids, values, themelioRecipient);
    // }

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

    function testDecodeInteger() public {
        // 250 with no padding
        bytes memory integer1Bytes = abi.encodePacked(bytes1(0xfa));
        uint256 integer1 = 0xfa;
        uint256 integer1Length = 1;
        uint256 integer1Offset = 0;
        (
            uint256 decodedInteger1,
            uint256 decodedInteger1Length
        ) = bridgeTest.decodeIntegerHelper(integer1Bytes, integer1Offset);

        assertEq(decodedInteger1, integer1);
        assertEq(decodedInteger1Length, integer1Length);

        // 251 with 1 byte of padding on both sides
        bytes memory integer3Bytes = hex'fffbfbfbff';
        uint256 integer3 = 0xfbfb;
        uint256 integer3Length = 3;
        uint256 integer3Offset = 1;
        (
            uint256 decodedInteger3,
            uint256 decodedInteger3Length
        ) = bridgeTest.decodeIntegerHelper(integer3Bytes, integer3Offset);

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
        ) = bridgeTest.decodeIntegerHelper(integer5Bytes, integer5Offset);

        assertEq(decodedInteger5, integer5);
        assertEq(decodedInteger5Length, integer5Length);

        // 2**32 with 3 bytes of padding on both sides
        bytes memory integer9Bytes = hex'fffffffdfdfdfdfdfdfdfdfdffffff';
        uint256 integer9 = 0xfdfdfdfdfdfdfdfd;
        uint256 integer9Length = 9;
        uint256 integer9Offset = 3;
        (
            uint256 decodedInteger9,
            uint256 decodedInteger9Length
        ) = bridgeTest.decodeIntegerHelper(integer9Bytes, integer9Offset);

        assertEq(decodedInteger9, integer9);
        assertEq(decodedInteger9Length, integer9Length);

        // 2**64 with 4 bytes of padding on both sides
        bytes memory integer17Bytes = hex'fffffffffefefefefefefefefefefefefefefefefeffffffff';

        uint256 integer17 = 0xfefefefefefefefefefefefefefefefe;
        uint256 integer17Length = 17;
        uint256 integer17Offset = 4;
        (
            uint256 decodedInteger17,
            uint256 decodedInteger17Length
        ) = bridgeTest.decodeIntegerHelper(integer17Bytes, integer17Offset);

        assertEq(decodedInteger17, integer17);
        assertEq(decodedInteger17Length, integer17Length);
    }

    function testDecodeStakeDoc() public {
        bytes memory encodedStakeDoc = hex'5dc57fc274b1235e28352d67b8ee4a30b74b5d0b070dc4400f30714cda80b280fd5fdd4268ccf9ed06fd481be5231b037e8efe905ff5aae270ee660c7240fe3205b030';

        (
            bytes32 publicKey,
            uint256 epochStart,
            uint256 epochPostEnd,
            uint256 symsStaked,
        ) = bridgeTest.decodeStakeDocHelper(encodedStakeDoc, 0);

        assertEq(publicKey, 0x5dc57fc274b1235e28352d67b8ee4a30b74b5d0b070dc4400f30714cda80b280);
        assertEq(epochStart, 499329790025850207);
        assertEq(epochPostEnd, 10267647615552527176);
        assertEq(symsStaked, 64716893496921337859207055163356700560);
    }

    function testDecodeTransaction() public {
        bytes memory transaction = hex'51010a1a82a7f70497fbbb549a63b4f11fe2062fc8eb78908138d5ec6c4c37b4d46d96020000000000000000000000000000000000000000000000000000000000000000feea64accf835d2e8c75071bb47bc74bde016d14c505b3263fec82f8b624f4ba9c01b20e506b5e1e868010bfd9908ba0027dbb1f063b9ef1f20cae1f75e2ccc9596eac88253175b1fedd531bfa008451b726a8125afd34db9e016d00fe49707269c1dd7303bae99ab55ffd4db401017b02ddce010105';

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

    function testDeploy() public {
        ThemelioBridge implementation = new ThemelioBridge();

        address logic = address(implementation);
        bytes memory data = abi.encodeWithSelector(
            bytes4(keccak256('initialize(uint256,bytes32,bytes32)')),
            0,
            0,
            0
        );

        ThemelioBridgeProxy proxy = new ThemelioBridgeProxy(logic, data);

        string memory uri = IThemelioBridge(address(proxy)).uri(0);

        assertEq(uri, 'https://melscan.themelio.org/{id}.json');
    }

    function testHashDatablock() public {
        bytes32 dataHash = bridgeTest.hashDatablockHelper(abi.encodePacked('datablock'));

        assertEq(
            dataHash,
            0x6ccea12fef78d2af66a4bca268cdbeccc47b3ee3ec9fbf83da1a67b526e9da2e
        );
    }

    function testverifyHeader() public {
        uint256 verifierHeight = 635523013169924;
        bytes32 verifierStakesHash = 0x47c966a84e5c672f89d5bf78d1b520623cff413b4895438a660adf9a8d0c59d6;
        bytes memory header = hex'ff68f5d720de3c9bc4fc6d015f129f27e2096fdc5879dafd32b06f20ed841b350ffd0553723b01420200715e2ff9e1a9efc9265b82e37a658856046faab9ba6b5259245313c11e6bc3cc08f666bbf1f4d54915ccabe7f0bfca8586a246f666dd765e802a685538271b6c9562f37105b664bba9d402f93bee65afaea8d3a127dec46be9c2c839c05eefa6fe992551b249637033dd297a8ff65e6740feb10f5741a5bb799e6ef90752dd4bd79cfebd9ac82b14393eca4d26624c1ba7a437284fc7371ffa9603586a9924210b85df6167da74c430805c5281366712d11402952dad81f520c7c9c17920752c33d5b405961c1568f4047810b6b5f9b18e3932';
        bytes memory stakes = hex'fdf24091d70b000000fdf24091d70b0000005b553507ad03ce7fb79e6f790a4ba12da396f120ac34ab0b4cee9aa5cdad9975fcac93be0ffd7573d85d05a821e0fcd356015bbd56a812454c6964c80a026cddf26933772a894f02b7fb32cc66174f92e38580fcc08ea704fd84af2ea800dff3eefc7d6755ee81dbab031d5dbf4a422545e5b2fef4eb5d6898db7994f79264a69d64da9ee27dfc114a3e06fdc8bb007f1c4878bffca0f769fa5f56d39f4b3368e7ce1bebe9be0c5c0fcbe87f3eba5e469909ead674c8cfe7b8fc6f3c5c01fdad6296c1636a9e7ffc5f31784a3580f4ad6fd15a76345f2ca10791bcde945dfd0bd5d129075c43bd378c464107fc51d59911fdb9cd5de5fc929f31fc63aa46eb311ffedcf4699e19bc334fcf4af27c349f5c9a4b28f44dcef0b82ab6dfaec310fcd942720cfd6e6e614a3a61440afc29ed56f363e3bf3f336b692a7cebb7bfad65d14f2f15e4e17caa25075463d4504db74866fc932afa08fde7fd93ed687d3fd7fc43559bdc5278acc47a554a22d327933345065485dbfaa330ccd894926f624b39a7e2ed64fc88962702fddc0f13682b26a26ffc0ea380497a7cec8966b197aaf8a31e6ad0192453d4fc2b393935dac36260e204c3858874fc9f752d09fd387f0a9e5cfe8938fcaa9f4afb1e2248cbc1ce49e11a149636d40c1a23ee1df091be24307ddd4c17c0f64d65c2fc74ae7712fd9071e1ce9a014104fc8aeb1a735ad3624abe9be37fa7b35b1332b21314c6c703530dfe2399690de41567252852fc63dd290bfdd6781ea4e5c25cb7fcfa6b4e9f27ce3347a2865e02acce1a468f8d7a1c72d16d22958ce9839c71f0c9e0c40a0cfcb81abe0ffd8d5728c5b915c4b7fc3db51868fcb7e5a1a5f6533345860c69b75b347d5d64a40bdcd387027288dfa05b7b5f2ffceedb4601fdf277790f0da09f1dfc9cab0a71e3777edf129ae9bad8db48110a25b561f04d863ae99596067bff5dcb8d33ca3ffc0c021209fd15f9405117adafccfc22155dd54397926d4c2d051a1be847da3a00711fe6e792ed4c26bec45592b93b72bdb575fc53a09508fd4a1c9609718deb2bfcae0dac864199d5f29d581cfc6a572e27fe27f8b3e6213ddd5492be830b8bb48dfa1f32a8fcf8941706fd122c61f088fc1c10fc204ab9142f21a53fb99a57a7e506fc0a26a9bfabf695f6688765b7b7afd0d7ef540c9963fc1dfdfc10fd5a3d7eebfaefba2afc1f33a2debde6c2865ef6f7dac20df64d4c52a0fdacf3266da781cf0a1b3ea9212a821ae0fc9c4a1e0ffd19a499f5ecb84242fc2b111079fb396a5158a1026402166f730ae2b9e356ece43bd06b4b0105dbf44e32a4bb97fc66bce302fd5c1c59464f8b61c9fc23c0e58c874864475e902c9e6de2e0e9e596d151ff96f44c49c66579d7416a1c36559734fc33048404fd68d52a14cefaef37fc62006d08';
        bytes memory signaturesPacked = hex'00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000028e384f787def153ae2a3ce2b06a484910aa40bfe31a6f7897542ae1c64bbdcdc2258150d341f9416b812d55682daba3c34d51581281c6d44c0b1cc8a5932b740e6dfc98ba7522a77fc9c6a871eb93868facf9e22de3af5c926adfe3e5bfa93a4c2a468d701a22e1c01f7e801a36bc6094e8dc07626138794a5e441bf56a67fe0fa0f1a492fb8c1036f9525fb79a9483cf9fa96d272e14f4f5f2ba521399845d70544f552c3df0fe333cafc814e4c613801b9e4979a515aef70ba710802b40de07bcd1dafc57ff679d512e9a51a2c05c4ee61079dcfd1d1b9d80266852f164f388f198e8ce172207993b732e03f4abb9c739c3a8920b3949b186889598a44eb304228f719f842d8279ee7045bdddde6894c27914b143b73590741604991f058b6f145f3aafc2fc56cd1e4b6db229d07707e10eb0a32246559475d3e7a7c642660b898e9e463a58e89303bb0196ba1cce0e59b18ecf51d9c1c4fe081ab0996f2c740bb975d634107bf3ae53f78e9a59cd2d0e3cef20aab55c5064fd38aa25b253009b7b1a474c8c84cd83b2147dbb4a69a496f6b8708ed7e3526d1395b71a448512f50cf84d1c05dca654a62f7707c6f71d52a19eeddb0626276a114a30ccc38b07e8aa675e18402b8fe81eefdcea99c828f5078de15d953a9827167e60f753df1aaae4b61bb5c86e538e73148fe185d1c83f68b39320220cbc6b3fd290831e720470f31321d4dc0cd6071cfa912f34ccbdc21f23f80cc43671e015ebce7fc9cbd59c015a5b7a32bc576dfb3a9ee175d866ca74a1cd4746849e21bec30af812f708db3f463ffacc86ca63d727999a8aa13b010e4eb86912d278557636db45d34bf5429e8034acbfc0d57cd7a8a939d9b2078589610ebe2b8306058bacfabe4d1f0f9424bb17e0dbff93fdeb9a88dbfa56486410b1529ecdfea1958ab3c3627346c49894562b0e1a291fc8c2f398685aa2744a0a6a4b7fd6265a16166f439e29af0b6240833c2914c1b937143fdcd319e59a1e08ea38c46a1e256d2d0bc443c3980ad57d67a86c63faf758f737a60c3564a8f1683b97fffd30fa586ca89b0881db01de8570f811a2fd4b04d9ee76069a1120dd9d2deb18e20fa4d22b07818809d6668eec8662fed3ac7307ed5b16210409a0daac85cac73f9652d8bfcc5dd43e9f0f3393476dda4189880cc9e3c44ee2e846b7ae82b68938c5e43560bef835c6143866935d22760f89b8702fba21cf355661a45767c760ce715f0b2b7d6447ea24046115b63d785486390d98aadbb70fc12fdfcb9c5cd591bb8d5b6c218bab87f367d3a656580bb6128fac0499aaaf855a5d19553ff9badc22067e334042dee4f8052bf7be3f16d07e4f49c81cc9446ed6f639772bb07749dfb8b71a2f69b2e82a548a70f60fd7e706f1296298d10f4271b75054aa683682ae46c41e743c7062c2051369e0b8540f81763d2c6b7b7b64bc22708933b0356f452adeb94e1cec697199dda5c94cf2057484d060e2c9e39783c36e82b14f91f940e31f5cd48637754b0d71a26814ae4478fb4af8d1bc976e2dfe92d9adea21f8fc94870c509b060f1b776495db919b06f6f4ad32f7fa007b78eb047866fa42f3e58e4395b115e36f29035fe85608a41135afaac1152bdb76fea0ceca8582855692b72b1bb5f33580c4f3428457a4c3a4f47492384e0d812f7be8577d79c2141e4be723a856a4d16bb4037cde8f6fd704fa684f8302abc0f64eb8e4e64920e8f96d18f07983d26734eab08783118c51d215b0569a739a310d41e0846a06171e7a3251144ae48fb19bd908';
        bytes32[] memory signatures = abi.decode(signaturesPacked, (bytes32[]));

        bridgeTest.verifyHeaderHelper(verifierStakesHash, verifierHeight);

        bridgeTest.verifyStakes(stakes);

        bool success = bridgeTest.verifyHeader(
            verifierHeight,
            header,
            stakes,
            signatures,
            VERIFICATION_LIMIT
        );

        assertTrue(success);
    }

    function testVerifyHeadersMultiTx() public {
        bytes memory data = hex'0000000000000000000000000000000000000000000000000013b3d9187e38e5a3f295e773e4fb2ed565cdcf10c1134ef366c19507f4521f1286564bcd24022500000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000001c000000000000000000000000000000000000000000000000000000000000003c000000000000000000000000000000000000000000000000000000000000000fdff0fb4bb573cc995906576e965c43f24e339c407f6481242e25d0605702d5aca32fde6387e18d9b313005a400300ffd449143e0929da73227d8011585b10f6d0d75b92552b199462cfd5347a1fe039c54340a2d93d87bc014ef4223d85126c19f44cea17c411d52dfbda1f1cee56b7abbf8f5785b260c05762fd509df7257cd66c15776998c3d1817ab7febf87e2f3ff9af82c6bb5d41259c3f7ecfeeb3ebd677fbc685418da41b575a4a12cfe3cb0115d3031771bb6004c3fb1ceec638de45735507c478b97d7e817255c2cd53920c1aa2835c5e2e68d0e09ebb5483f76fba151c7e0a187533fbb1045a58809450b40d38771ae7bc524f9a8954763cd00000000000000000000000000000000000000000000000000000000000000000001ddfd9164353a03000000fd9164353a03000000261dfb4a2367c173877e513b254cfd95572a022067bb7bee2eed67abf94297edfc5934bb11fd5117ef21e978567ffc9db91391d376ab1f4134a295e32f580c3eff39de75cb2a1b74c8c9a00e70c3b9b61fa1b8fcd776eb35fd385ee28f4a307ebbfc169a4f0c3b4199b011a9e5c3799677f2e55c3310733815f86dfded2cd52af8f5ef937933fce9949c92fd2323693b1f473a1dfca41b20d99f1e17264c4f76a5822d874397c9ee1b414b5618c516c7d417b00be55c7b3f37fc845c4d1cfd2f7a7e008cf28de2fcb0564c1c300fc39e8511f2d38dbf7ab238b03613a756861226246dc4823b80e741800a04fca266285cfd915a27ecd4e8b19efcb1a8d9279d400b50136558323cc59ad8238b90a27056b0b2f0274dab7eab662eb9de49f5fcd948d06afd3289d99a6d67157afc04e1306d0247bc71da81d3447b3963cc22dc686881eda142fb58f260b6859ec8b66af0b3fce72d5d0ffd8438f6817bdb7751fcfbdc761da822f2df690c0a58690ba611f26f051473c27333a398913a5a890ed31b389e03fc5c87ae2ffd8514c8055893d9f6fc39595117213af4983f0863c466327a8ae7aefeac90e6510ac4852b031185b6f7f93f6b74fc3c36dd2afdf90c20035ea7c070fca1de92dd000000000000000000000000000000000000000000000000000000000000000000001280ed9290805db5687757e07295d91a9f3a90c7df48df978991d79f6b82101f37c90bbc7450a02886aee4725340c1477d1e73fc99b71c2f8f4afd03cc2c95cb0771efb64a8cb074eae4a392b004c21c900091a6178dbfdad282e2e79eceaf406ecaf0e4f0b28d797d30ce05aba06ae2c678829150394bee80887f0c01741ad90e402ff5b88dbad8c8fe09836fd1e9a37fab197cacc13c619cb86ec08a4d8d2fbf58cac8364771f1fde5cec53e689940fa434c2fda9bcc37138e75171681f5110123425a8d41e60f693c0d5169ab252ce519f9ef4d3193bcd89b404847f6c0f385fe1e76095af13088ae202f7372bc73c3417381a37fd208f06ab3ae322c773c06dc1a3907cbc071c6b7b08d5ed26c69214062baf88406febcff42ceb2563ec155abe03ee2ca8c18450a148e90a9ca784f9aa17711d84476e218989b08b6e78c0118b39dc2fc2c073e1f273d8799308373e0387e95abbd98b166f8b6f31ea923b832b2878b8ad1d22178aee081f1bd36fdfa0dfaaca4a16548267991689970d80d6c0d671a0e7fd0a67d431254f604f61c61f3771acc1a8cd3755344d22b2ca9fc3e82d7e95eca153c57417a8e005000c35589561c7ebf6716032eebc165e40203ccfdba1146d2c317c96727d887f7c90ee797fe24fd6de58b5187b45a8c2d23a96ebde0b40a61442953c2a33fcdb90cc3f9a5d509b9e59980008ffd83c267b90eaba3ca1b5dc6454f1dda0de24dc7e6544f424a07c89c34d369e352b88ae0d63306714ec69db838825cf10ee846c4e6e54a1a14e1845f9c58fbbcdea0dc389c0b';

        (
            uint256 verifierHeight,
            bytes32 verifierStakesHash,
            bytes memory header,
            bytes memory stakeDocs,
            bytes32[] memory signatures
        ) = abi.decode(data, (uint256, bytes32, bytes, bytes, bytes32[]));

        bridgeTest.verifyHeaderHelper{gas: GAS_LIMIT}(verifierStakesHash, verifierHeight);

        bridgeTest.verifyStakes{gas: GAS_LIMIT}(stakeDocs);

        bool success;

        while (!success) {
            success = bridgeTest.verifyHeader{gas: GAS_LIMIT}(
                verifierHeight,
                header,
                stakeDocs,
                signatures,
                VERIFICATION_LIMIT
            );
        }

        assertTrue(success);
    }

    function testCantVerifyHeader() public {
        uint256 verifierHeight = 1749110936825120;
        bytes32 verifierStakesHash =
            0x9a2cc9eb108a14202a749b201da4dab5eafa1d72d8818f4f67f7cc6b3f4585b3;

        bytes memory header = hex'ffc0e0c667f78948df7164ea7220e59d0679aec9345a16cab3cf9fa01ae7230eb2fd21ed0fa0ce36060056f4b83a4e5db252f5fe3810453affe208f9b8620f62b0ee543cc64101c26ba08118849e005258b677ddb0f57b6e6aa4af75745c2dca4c0f5d0302638c28ab21bc58b17e9d56e6cea11ccc4bfa42c4a1a330fb0c58a8da086744de73b04db321fed0351f6fee8dd421d2ceda7e17e5310ffe8aa3ebbc3ff5601d2ea03468c84d9e81fe4d9521d9a7da862e8bd425956d33546a5a6cb78b7ee8209759cebcedda5a66cbc4929e906b8a579283df78b64cb78c60406e01278d12397af71135a226963a47b2512df1dd5760b952e64e61ca97efb7';

        // the stakes for the header's epoch total 387 syms; consensus requires at least 258 syms
        bytes memory stakes = hex'fd6e04ece002000000fd6e04ece0020000002d8ea4c3ad09070cac09cc5ec9df767e7cd95c5bdb8524d6da119e5d646a2e96fc2995aa07fd45e46abe8bbc04dbfcb2c42c53393082157f0d64f9e814369662692c8ef650399b634d900f7dc366b6e148e007fc53f12300fd2af9b1f62acd67cffc328636c9300a6c1fb3012d51584b96ee80af6dda06666a87ee55be73e9f127641709403ffc97284d30fdd9cdd3e41864f3b7fc1f1e815176404024abba884cb5797dc16ff7ee56586c9a98073ad9126e8c9b064f1a81fbfc69e0e806fd29ade4e2ad6e2ef0fc89de34a63e3f7527380c72a85bb877f1027992aea23e32554f2a140d8dd3083cba95ee48fc5ab22d1dfd8476bab34467502cfce2bcd2cc';
        bytes32 keccakStakesHash =
            0x36d3b289e1875df8bb587447251147525e54d1cb630ae4c66e72d272e5722c8b;
        bytes32 blake3StakesHash =
            0x9a2cc9eb108a14202a749b201da4dab5eafa1d72d8818f4f67f7cc6b3f4585b3;

        bytes32[] memory signatures = new bytes32[](10);
        // signer 1 has 1395442866 syms staked during the header's epoch
        signatures[0] = 0xa5638c64fc9e472ab5a10bd2241a1feed2b3385b5eef4b3a25e8295d9a74ed86;
        signatures[1] = 0x8d9c8b7f533f2e09258f026068cc7795af79977f62ff9d513723723666927b0e;

        // signer 2 has 3375793714 syms staked during the header's epoch, but we will zero out his
        // signatures to simulate not having enough signatures to verify a header
        signatures[2] = 0;
        signatures[3] = 0;

        // signer 3 has 1367416351 syms staked during the header's epoch
        signatures[4] = 0xd46c598158a3fd666c704ea881df3381b51525e2a3d3cb62903885ca2029f5c9;
        signatures[5] = 0xd220aa4dc4dba24744b1a85a739da6d4050087e5c3b2e82a296921d74282fc0d;

        // signer 4 has 2788482697 syms staked during the header's epoch, but we will zero out his
        // signatures to simulate not having enough signatures to verify a header
        signatures[6] = 0;
        signatures[7] = 0;

        // signer 5 has 3436362978 syms staked during the header's epoch
        signatures[8] = 0x5bc6cd88bd7a794ce698abeaf46e6e71b3fd3ebf5e3c7ceb7bcd8df5153a9b69;
        signatures[9] = 0xd564664daed9e51fa1a59cfef8bc45f9f5174b44ebb82fc952c03a38696e2302;

        // this call saves the staker information in the appropriate epoch for this test
        bridgeTest.verifyHeaderHelper(verifierStakesHash, verifierHeight);

        bridgeTest.verifyStakesHelper(keccakStakesHash, blake3StakesHash);

        // expect a revert due to insufficient signatures
        vm.expectRevert(
            ThemelioBridge.HeaderNotVerified.selector
        );

        bridgeTest.verifyHeader(verifierHeight, header, stakes, signatures, VERIFICATION_LIMIT);
    }

    function testVerifyStakes() public {
        bytes memory stakes = hex'01f3f5ce31ad81eb931f650b8ed28391e3ad5aed976e1c3eee2deae6742116edfd771094398f929904fd44c797252c32eb62fcfad60898e36bb7d8e487f739b106f90752f3b600d9dfc7730648e9393ff47874bee6dc7ffd9b003a187f9d582ffd87858eff7318e4d4fca9b9aaa809df64970bdae36063da9473f6a3a74557276fab21cd261fbf4aa67b8c87f0dffd085178637beaa836fdde321617bfd48f91fcb2d3bc0702a81c22937020f6419ae7147f0b698755ba09afafd4d7e79e9ea05f47e5f624fd9a55ff651490541dfd131cbedcdb0340a4fcd32bd0ee784a63e58563d9b96d250b836e70f4b2e2aade20c3efe4f38a146c447ab447b7fd3eb1005ad5a1e404fd42790cefa4aad592fc41552389b513614ca930dbd7fdd2bfd11d59d29760ee5c1413c19189077fd593e3098315fd7039c9a22f164f0bfd9a799fb415ff9edffcb49e4d971eff0b390b03782062066ca2133a48ff3868fc61b06b7aee0893d46b5977fa14fd5d036c5da9d9012dfd3178127831674c95fc1e6b9f10';
        bytes32 keccakStakesHash = keccak256(stakes);
        bytes32 blake3StakesHash =
            0xa5765ec3667c460cb610b5368fd2ba18917b2ed14fa998cce6cc95820911ec54;

        bridgeTest.verifyStakes(stakes);

        bytes32 savedStakesHash = bridgeTest.stakesHashes(keccakStakesHash);

        assertEq(savedStakesHash, blake3StakesHash);
    }

    function testVerifyTx() public {
        bytes32 transactionsHash =
            0x06ce98f3e4cc2aa771819b1d7d500105aae8be388f7ecd7bfb83e3d1a4e1f01d;
        bytes memory transaction = hex'510e60ce4756600da82eaa99661a144a0f34cbf1a2b67f9076508e09e003c18671c5b5a49f869fd8e7af7037421d1f1655870577f3814ed75b6b970cf21745221662c7e6041adb1e5e489d3927e1b18098cc432edd82a0cbbfab5fe18e664e84bd4f64b311538320cb90ea84cc2275700c37c1ffd1001f2d4a13c0dc733e240586dd94b4ea4bfc4fdc2a4a5f369de1ca125d93bc22a0310cc402f9eb383ecbff3c5738ed98a98a14c7efeed973104cbb496c88050b46982a7de0be08048fde3593704e6f1e2a99e10da56f76f46c2495a981c4f113462373363508b4effa0c8862f063adde54f07f6ee2371dd12bf6fec88f685f5a1fdf84d8c8688bd47521c0c079d2d6a865d56a30007148ee7a443cf5d10ebc877894099c57aea65c4b87182d0411e1569d14abde0bd371cd47b91a79cd79d84158ee0576d0bab20d67c3cec94894de1c09e9ffc3ab9f34cfe0d89b48959d52c59ae8d70774f4c298423a1d4660509cacb86f7a6368f481561ca328351fa670b13e06d6e9487d1cb7a5f80615235b74f28f53a7f634c455a5ba9b80e70d798ea2aae16bb5b340d058580ad9f0889d50a1bae76f5e7334704525cf1373d15277ca35473bdd1de537d56a0b0cf046d54127d2be37109f573d8530c82f190000000000000000000000000000000000000000000000000000000000000000fefd5430d14cabfd7c80c59b3f49d2f3570173145bc1bf2c473165df2238c8fe18ad35bc38652a216ab0660df5943ec0169becdb6e45d25a527410b78a63141ea5b15584165868d0fee255b69e79e3e5c74b871aa2ef4207f5016414473ff5d873f7962ac0647037d26c15afb18fddbae5e014f03214511d788c7c40fa21e1c210daf21ebaa0276f549b1124c76353d3fee1e1a082ae8fa915e68b255942beb62920307477148af56639bc428c9ccdaf8011e7aa336122e37a96d6af822794ac5bbb14494ec7c77e52f79e05a413b6f044cd48a26e1522ebb406090b7f847e50b9b11002eb601f8fb71f61fab28cf9ebb2d03113e960dbfeca595d01064e87a0f4545fd36a509a9b20dcd5ca24b7328d625e4609b58c513edc905fc21f5148851c81f45879e690406a14535f3c76a3a0a85e77cd570a021949fc85bc9e1364ee71b2081fed4cd694b57b378f584f4b8b2c0e4f36f5a0d2a46b5bc19bded7fe4babbad70fad0c86fa7723a6aa2819e4016d14df7ee8759a0c4ebd6fcf62d2d7c28a4515a1df5a63c14cfcb4e4c71f29c7b901dee255460fca18928316d8c701575df0366cd250fe466e390cc8070c5733871ca437e27ce820c385c95c7a39d39cd2e609ef9562baf9ee183b9bc9a5e120ffa48800427af56a1425509ff9043db8b39cce5c1c5f3bc9bb299a44c59696f51c8a2efad1ada0f7deb5e41c71f6ff8230b95fe2e82af05b30f9a0cf12fe2dbe07e0de65612f1a7d3f13f21ebdcf0173148a886c29ae66ea029dcb23afa19765104c80f6cba8e8eb0c88dd78f97ebcb4256ad69610f9e9513af1cbcbd4e5f64afb2b1fc804fee35d686420864ccc2aa5d8005e8c1a56016414ebff03cd18efae057c121666177cedffef9acd734cd25c5cc65021870ffbaa65fb22e1c01f6d65bd5a5cc3165a050da4c346a081fe1a90fa8c80fba1d93c08a0b98d3563bb017314701eaff2d59aa9471173d5a7e1e4cb54202da38fc6b6326074175477846558f16321a82d85f3ddc6c2155c4840bac8be31147718fe8d61ad270311d38410dda5a23ead3fb6016414b897e61ae19c8ac17a92c157c3c14a66bae4298b68f3e77bc0fde1716af82687eafd30a022a07fcc5aa8048c5668e77fe6505d0cfeb3f52ba13a3f463d782f19877350850c016d14966fc962b28f59958bf62c6404372784147ccc0b1c4cf90fc30082f67b4416a2d3295954c95cbea5dc82cb3708055a2d06a175fcfe093ddeee90bff35d7f5df1214fdab364016d140573e2bc7a4519515664b086dc4a21379e0afaee280dd2ecea598dd82c1c2a9f45d0998efeb6d7c204341ba6fcd6835169eef3d2fed9c53e076f1b5e6d87c21620bf92bab1016d1483d684c0d099f569cec53eb845c46535ce19a28cb35425d645ea10906132abfd3c3989fe16ce8c14df677db342aed5361f2dce35fe02eedecca2114ce1a31ffe9fb818787f017314c24c34dd1100c233615e0a2550f99567ddeeb813db0ccbe19e8d6d63a6c19984efc5ed5ecf9ce2087d731b7df35ca071caab17c3fecd2d8f49bcdffaeef7de96a72a0ced4901731485a05cbaa21dbbbc6b335ad60a2d493d0daa1b372b32df345d5c12721b38dbd93d581969bd960ce6fd5ca60ea869c0bf3c7ff1affeac440e0f0ae873c9ffa0272e65ecf341017314d7a61aa8bfc16069ab3987b54266524595d3e955427db21fad161dcd3d60d1cd24e01456650440c0b443e9b7195420a96e01ff94fe01878d44cd7d63600384074a16a6b85a016d1403eb953e3ef2ce6813c1b966bf751e357cb6235be7e168f9e41c8a1284f245c746b6321684d2f3d338bf453280b214984fc7316ffec302503c22fe0e798cbc2e20a80b402d016d144ae7f4c63e85e5ed01ab4b35de1bb4d19db84052de1efed65f63289b2bc831ed39ef707add78149f3b49cf698b749466ac481411fe31eedad65ce8e01b68df5aa05d4c1dc0016d14848bd6c5f2cc77a9d6bd17d84db9472223d7e11d2f93f71491c7f87805d4c2058ac6fa384192144ee713ef4d3311ad55a4fd2383fefabd0e5f4b69a0fe48c26f953924bfe2205329d14c19af72f1491d8abec8233a97889b6f7cf3346a7bf716901f77704f3f147b685ccfbe5bdb3f4b44a865fd8b3875ebae650e91f3658dc92e8804829de885ef2cfe751aab97253acc6c425ec8423103670a4afec74fc5133d00d006de452485f430d4d220c137532064216e1792a83cbedcd83a10830eeab11795f8abb772f511cd04ee66144e59647e8beb9ef384188b3e97a8a9df1fba480d8f8b1cb39b036df1fc2cc13e0692eb7c6e2a3f6c8bfd0737639ed5b83959151afe2f6242c049d90746cb400fd6a6f00cc40173149282d382fba00f404b238fe70ad3685ac79ff101973c69ab7d5cebf476bf600094d5a14a2598bece867979f0987673ff58c7aa0afe7a957aaa09339cc5daadc4eed3c0e5e0016d14d598c1f977fd7181ba9a5edae1a7022f80838d3f375068373e9de79fc3eb6112f887d2963289b38dbde4901a4e5fd3271cebade4fe5cebd5cc1dd6570f1d736bead4315378203cc8f350a4322ed7e338e57b83cb381cdc6180f16ef65933327de3d2213fc73914bdf2e248aae45f05d739be9cc4ac71b3a17b7ef64e87b14e9352814811202a2ca6860be3f183265f9472cb32888d0ca1235409d5fee15c451b31f3abd7409523c6d65f89fb016414cd9636a20d05da60542cc589c2088b25d8ae4f72fef9111183da0c08a78c1344c5b5a38251021752dcba9c540548796f6bf7ed012d39fbbc66af3da5203f13d32dbbe760a3e5cfdcab828fee31d7fcae6727028761121e8db4e4e2c0ecdc6970e6de8ccb6372a01c811e941e9b01d08f308b1ed74b1dd8b0303ccaf2d1a5d18009a1bc8fbea82e88d481b4befc25d70d917a491877c478dc07157ef82bae0555cb7dc0cd88fbfd02b30fefe113d64cdb0b24e5d4e8479833cdf861401a5f98140aa96240cdb23895ae6983056da2652dd1178f130040ebc477d9c0ca0cf2450d59e880f9c742308e7c0d3b4b7d28e7907a2c9fca01f7ed1a657f536e1cdbf806624dd429245b3368a0579539b81040a093d60005532635fe2105a8c0c664ac0cfc9fa7a5b6d57ea69b3612780f88ba241b64b507a3b36729ebcacd0b082b2f8c7cef34b0411fe971144616558f2e06b87cc774eb3284d88a33f93a82ef3bb011c27c9e569106b6c431bceb7a194bbe35d99d960e564047faa69213c48b4f59e0a4ed588ee560';
        uint256 txIndex = 0;
        uint256 blockHeight = 9585859282281084318;

        bytes32[] memory proof = new bytes32[](2);
        proof[0] = 0xf8ec7c82ed3b27af595208fc8c81f7c48dc1fa9dc5ef01f1f58c4c275e24eb5b;
        proof[1] = 0xda386f69440cc2de10283ed5755ff931a31df9312028a08bcf4b17d0fbcae362;

        uint256 denom = SYM;
        uint256 value = 116908828879270146245621714886765597949;
        address recipient = 0x5BC1bF2C473165Df2238c8FE18ad35bC38652a21;

        uint256 preBalance = bridgeTest.balanceOf(recipient, denom);

        bridgeTest.verifyTxHelper(blockHeight, transactionsHash, 0);

        bridgeTest.verifyTx(transaction, txIndex, blockHeight, proof);

        uint256 postBalance = bridgeTest.balanceOf(recipient, denom);

        assertEq(postBalance, preBalance + value);
    }

    function testCantVerifyTxTwice() public {
        bytes32 transactionsHash =
            0x06ce98f3e4cc2aa771819b1d7d500105aae8be388f7ecd7bfb83e3d1a4e1f01d;
        bytes memory transaction = hex'510e60ce4756600da82eaa99661a144a0f34cbf1a2b67f9076508e09e003c18671c5b5a49f869fd8e7af7037421d1f1655870577f3814ed75b6b970cf21745221662c7e6041adb1e5e489d3927e1b18098cc432edd82a0cbbfab5fe18e664e84bd4f64b311538320cb90ea84cc2275700c37c1ffd1001f2d4a13c0dc733e240586dd94b4ea4bfc4fdc2a4a5f369de1ca125d93bc22a0310cc402f9eb383ecbff3c5738ed98a98a14c7efeed973104cbb496c88050b46982a7de0be08048fde3593704e6f1e2a99e10da56f76f46c2495a981c4f113462373363508b4effa0c8862f063adde54f07f6ee2371dd12bf6fec88f685f5a1fdf84d8c8688bd47521c0c079d2d6a865d56a30007148ee7a443cf5d10ebc877894099c57aea65c4b87182d0411e1569d14abde0bd371cd47b91a79cd79d84158ee0576d0bab20d67c3cec94894de1c09e9ffc3ab9f34cfe0d89b48959d52c59ae8d70774f4c298423a1d4660509cacb86f7a6368f481561ca328351fa670b13e06d6e9487d1cb7a5f80615235b74f28f53a7f634c455a5ba9b80e70d798ea2aae16bb5b340d058580ad9f0889d50a1bae76f5e7334704525cf1373d15277ca35473bdd1de537d56a0b0cf046d54127d2be37109f573d8530c82f190000000000000000000000000000000000000000000000000000000000000000fefd5430d14cabfd7c80c59b3f49d2f3570173145bc1bf2c473165df2238c8fe18ad35bc38652a216ab0660df5943ec0169becdb6e45d25a527410b78a63141ea5b15584165868d0fee255b69e79e3e5c74b871aa2ef4207f5016414473ff5d873f7962ac0647037d26c15afb18fddbae5e014f03214511d788c7c40fa21e1c210daf21ebaa0276f549b1124c76353d3fee1e1a082ae8fa915e68b255942beb62920307477148af56639bc428c9ccdaf8011e7aa336122e37a96d6af822794ac5bbb14494ec7c77e52f79e05a413b6f044cd48a26e1522ebb406090b7f847e50b9b11002eb601f8fb71f61fab28cf9ebb2d03113e960dbfeca595d01064e87a0f4545fd36a509a9b20dcd5ca24b7328d625e4609b58c513edc905fc21f5148851c81f45879e690406a14535f3c76a3a0a85e77cd570a021949fc85bc9e1364ee71b2081fed4cd694b57b378f584f4b8b2c0e4f36f5a0d2a46b5bc19bded7fe4babbad70fad0c86fa7723a6aa2819e4016d14df7ee8759a0c4ebd6fcf62d2d7c28a4515a1df5a63c14cfcb4e4c71f29c7b901dee255460fca18928316d8c701575df0366cd250fe466e390cc8070c5733871ca437e27ce820c385c95c7a39d39cd2e609ef9562baf9ee183b9bc9a5e120ffa48800427af56a1425509ff9043db8b39cce5c1c5f3bc9bb299a44c59696f51c8a2efad1ada0f7deb5e41c71f6ff8230b95fe2e82af05b30f9a0cf12fe2dbe07e0de65612f1a7d3f13f21ebdcf0173148a886c29ae66ea029dcb23afa19765104c80f6cba8e8eb0c88dd78f97ebcb4256ad69610f9e9513af1cbcbd4e5f64afb2b1fc804fee35d686420864ccc2aa5d8005e8c1a56016414ebff03cd18efae057c121666177cedffef9acd734cd25c5cc65021870ffbaa65fb22e1c01f6d65bd5a5cc3165a050da4c346a081fe1a90fa8c80fba1d93c08a0b98d3563bb017314701eaff2d59aa9471173d5a7e1e4cb54202da38fc6b6326074175477846558f16321a82d85f3ddc6c2155c4840bac8be31147718fe8d61ad270311d38410dda5a23ead3fb6016414b897e61ae19c8ac17a92c157c3c14a66bae4298b68f3e77bc0fde1716af82687eafd30a022a07fcc5aa8048c5668e77fe6505d0cfeb3f52ba13a3f463d782f19877350850c016d14966fc962b28f59958bf62c6404372784147ccc0b1c4cf90fc30082f67b4416a2d3295954c95cbea5dc82cb3708055a2d06a175fcfe093ddeee90bff35d7f5df1214fdab364016d140573e2bc7a4519515664b086dc4a21379e0afaee280dd2ecea598dd82c1c2a9f45d0998efeb6d7c204341ba6fcd6835169eef3d2fed9c53e076f1b5e6d87c21620bf92bab1016d1483d684c0d099f569cec53eb845c46535ce19a28cb35425d645ea10906132abfd3c3989fe16ce8c14df677db342aed5361f2dce35fe02eedecca2114ce1a31ffe9fb818787f017314c24c34dd1100c233615e0a2550f99567ddeeb813db0ccbe19e8d6d63a6c19984efc5ed5ecf9ce2087d731b7df35ca071caab17c3fecd2d8f49bcdffaeef7de96a72a0ced4901731485a05cbaa21dbbbc6b335ad60a2d493d0daa1b372b32df345d5c12721b38dbd93d581969bd960ce6fd5ca60ea869c0bf3c7ff1affeac440e0f0ae873c9ffa0272e65ecf341017314d7a61aa8bfc16069ab3987b54266524595d3e955427db21fad161dcd3d60d1cd24e01456650440c0b443e9b7195420a96e01ff94fe01878d44cd7d63600384074a16a6b85a016d1403eb953e3ef2ce6813c1b966bf751e357cb6235be7e168f9e41c8a1284f245c746b6321684d2f3d338bf453280b214984fc7316ffec302503c22fe0e798cbc2e20a80b402d016d144ae7f4c63e85e5ed01ab4b35de1bb4d19db84052de1efed65f63289b2bc831ed39ef707add78149f3b49cf698b749466ac481411fe31eedad65ce8e01b68df5aa05d4c1dc0016d14848bd6c5f2cc77a9d6bd17d84db9472223d7e11d2f93f71491c7f87805d4c2058ac6fa384192144ee713ef4d3311ad55a4fd2383fefabd0e5f4b69a0fe48c26f953924bfe2205329d14c19af72f1491d8abec8233a97889b6f7cf3346a7bf716901f77704f3f147b685ccfbe5bdb3f4b44a865fd8b3875ebae650e91f3658dc92e8804829de885ef2cfe751aab97253acc6c425ec8423103670a4afec74fc5133d00d006de452485f430d4d220c137532064216e1792a83cbedcd83a10830eeab11795f8abb772f511cd04ee66144e59647e8beb9ef384188b3e97a8a9df1fba480d8f8b1cb39b036df1fc2cc13e0692eb7c6e2a3f6c8bfd0737639ed5b83959151afe2f6242c049d90746cb400fd6a6f00cc40173149282d382fba00f404b238fe70ad3685ac79ff101973c69ab7d5cebf476bf600094d5a14a2598bece867979f0987673ff58c7aa0afe7a957aaa09339cc5daadc4eed3c0e5e0016d14d598c1f977fd7181ba9a5edae1a7022f80838d3f375068373e9de79fc3eb6112f887d2963289b38dbde4901a4e5fd3271cebade4fe5cebd5cc1dd6570f1d736bead4315378203cc8f350a4322ed7e338e57b83cb381cdc6180f16ef65933327de3d2213fc73914bdf2e248aae45f05d739be9cc4ac71b3a17b7ef64e87b14e9352814811202a2ca6860be3f183265f9472cb32888d0ca1235409d5fee15c451b31f3abd7409523c6d65f89fb016414cd9636a20d05da60542cc589c2088b25d8ae4f72fef9111183da0c08a78c1344c5b5a38251021752dcba9c540548796f6bf7ed012d39fbbc66af3da5203f13d32dbbe760a3e5cfdcab828fee31d7fcae6727028761121e8db4e4e2c0ecdc6970e6de8ccb6372a01c811e941e9b01d08f308b1ed74b1dd8b0303ccaf2d1a5d18009a1bc8fbea82e88d481b4befc25d70d917a491877c478dc07157ef82bae0555cb7dc0cd88fbfd02b30fefe113d64cdb0b24e5d4e8479833cdf861401a5f98140aa96240cdb23895ae6983056da2652dd1178f130040ebc477d9c0ca0cf2450d59e880f9c742308e7c0d3b4b7d28e7907a2c9fca01f7ed1a657f536e1cdbf806624dd429245b3368a0579539b81040a093d60005532635fe2105a8c0c664ac0cfc9fa7a5b6d57ea69b3612780f88ba241b64b507a3b36729ebcacd0b082b2f8c7cef34b0411fe971144616558f2e06b87cc774eb3284d88a33f93a82ef3bb011c27c9e569106b6c431bceb7a194bbe35d99d960e564047faa69213c48b4f59e0a4ed588ee560';
        uint256 txIndex = 0;
        uint256 blockHeight = 9585859282281084318;

        bytes32[] memory proof = new bytes32[](2);
        proof[0] = 0xf8ec7c82ed3b27af595208fc8c81f7c48dc1fa9dc5ef01f1f58c4c275e24eb5b;
        proof[1] = 0xda386f69440cc2de10283ed5755ff931a31df9312028a08bcf4b17d0fbcae362;

        bridgeTest.verifyTxHelper(blockHeight, transactionsHash, 0);

        bool success = bridgeTest.verifyTx(transaction, txIndex, blockHeight, proof);
        assert(success);

        // expect a revert due to already verified tx
        vm.expectRevert(
            abi.encodeWithSelector(
                ThemelioBridge.TxAlreadyVerified.selector,
                0x7ad10736f104fa8f02e862ea053cd3ab2cf363848212eb4c00018d6cf4e17f63
            )
        );

        bridgeTest.verifyTx(transaction, txIndex, blockHeight, proof);
    }

}