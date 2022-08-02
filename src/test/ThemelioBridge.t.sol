// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.13;

import 'forge-std/Test.sol';
import 'openzeppelin-contracts/contracts/utils/Strings.sol';
import './utils/ByteStrings.sol';
import '../ThemelioBridge.sol';
import '../ThemelioBridgeProxy.sol';
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
            uint256 symsStaked
        ) = bridgeTest.decodeStakeDocHelper(encodedStakeDoc);

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

    function testHashDatablock() public {
        bytes32 dataHash = bridgeTest.hashDatablockHelper(abi.encodePacked('datablock'));

        assertEq(
            dataHash,
            0x6ccea12fef78d2af66a4bca268cdbeccc47b3ee3ec9fbf83da1a67b526e9da2e
        );
    }


    // function testverifyHeader() public {
    //     uint256 verifierHeight = 0x183fbb57d5fe52;
    //     bytes32 verifierStakesHash =
    //         0x52bf0665451a2df0c62e7b57faf3fa93eeebd00a595ec124fd187790dac4278d;
    //     bytes memory header = abi.encodePacked(
    //         bytes32(0xff8d5e99a13192a02d28fd80d3bf4e607d9bb232cbe681868d6bcbbd2058b86f),
    //         bytes32(0x10fd53fed557bb3f18007200ba6d4739bfd685ce253c94530b3c8aa309a8ed1e),
    //         bytes32(0xe12d2326c6acd39f86031580059da0045acf505fec7d15ddf3f3eb30b66cc6f2),
    //         bytes32(0x165323d1aa82d35248aa7d6ab6d2d69d0ee38160b317063a231bbc239611a563),
    //         bytes32(0x3197f8715d07882b82a3feb60bebef9444aafd4a39b714eeac1f5afe97adc6be),
    //         bytes32(0xca073cd05eb3ad48a00663d2fea825ca078019191a436fa10ef129a4502b710c),
    //         bytes32(0x3eccc3aeb2b86647da1cf1599cca4fdd9d1deb7e1b5b1da2986fa3cda412ac2d),
    //         bytes29(0x7176a115d25f40e9fc66338d970a37ee37c835cfaac452931c7182391f)
    //     );
    //     bytes memory stakeDocs = abi.encodePacked(
    //         bytes32(0xfc75460291714ea3c5dd8ddc0eaccd185fa5939c4607c9ab7f03c05e756e4e91),
    //         bytes24(0x9e15793eb2fc5504783dfd39c418915273fa44fc75460291)
    //     );
    //     bytes32[] memory signatures = new bytes32[](2);
    //     signatures[0] = 0xbfab48aab1c659429e15b4be7fe49f4e671b224133be228c1c76ca75a03f2d47;
    //     signatures[1] = 0x7cd99162097711e409526ec81dd2ab6ee1b56cf855da7355c365a142cf86b50b;

    //     bridgeTest.verifyHeaderHelper(verifierStakesHash, verifierHeight);

    //     bridgeTest.verifyStakes(stakeDocs);

    //     bool success = bridgeTest.verifyHeader(
    //         verifierHeight,
    //         header,
    //         stakeDocs,
    //         signatures
    //     );

    //     assertTrue(success);
    // }

    // function testVerifyHeaderMultiStake() public {
    //     uint256 verifierHeight = 0x10b748b2f980a8;
    //     bytes32 verifierStakesHash =
    //         0xd0dc52accc736b78b7e97f44199a7d2e13024f97cd307592e4e0c1806f18f419;
    //     bytes memory header = abi.encodePacked(
    //         bytes32(0xffa5ca33cac8a871c126d6ea90817f61b3fe6dd8f989279fd2b722adcf9aa928),
    //         bytes32(0x4bfda980f9b248b71000cc29cb82a4ce59d145edc182cc1487b4625a7731e8d0),
    //         bytes32(0x085590a13e13f63a54573685ae577e5074cc9fc5c27f48437dba33ed1bb80516),
    //         bytes32(0xc5de0ce4d2825a2f9bf51b3db745c2aea7e82e8e6cdb64af80028e726a1b5d60),
    //         bytes32(0x4edf6834f9d4ddf8085bfe09d7b23bd7ea2a323d48c3f3a2b87f1cfeaaa9d312),
    //         bytes32(0x687b1ef6b7632cdcf93fcaf4fe8b7ed3e41dd54df3272765c4bc0939bc734819),
    //         bytes32(0x017a69884bdec1865a595b8fd861c9b0775fd5f67d786987efe1081d441e2802),
    //         bytes29(0x9dc372cc3c1bc96439c6d67286c8f66c63a81121a3dec7e64bad8550fd)
    //     );
    //     bytes memory stakeDocs = abi.encodePacked(
    //         bytes32(0xfc724fb1579e572480f4b8e7832dccaab7d6ba5d50cf41b112e3c4c2e33cf9d4),
    //         bytes32(0x82f3c38b80fc619fd053fd5919c909ec06c89dfcdc06bc316fbdb2f38cd7a46f),
    //         bytes32(0xeb94920535bbd928c672227a6c2222a97277c0609c1a6141fc5a4cec34fdc43c),
    //         bytes11(0xae4dc12a184dfc9648f525)
    //     );
    //     bytes32[] memory signatures = new bytes32[](4);
    //     signatures[0] = 0x5b8d4eb42a989be6ab99a89f2568c698051e149505849948299ba5034e2468f9;
    //     signatures[1] = 0x46d6d6dceabe0c8973d63eea075b395171d05d39e7f21bd7f8d2448e03ecb001;
    //     signatures[2] = 0xc82e64734286625395420544394730c911c6a5a41ab8b189b60b21d58e1e9b0c;
    //     signatures[3] = 0x14062b1bd5bd7edd00c1271d24bcff275ff355e1111cb7306de87251bf8e5f03;

    //     bridgeTest.verifyHeaderHelper(verifierStakesHash, verifierHeight);

    //     bridgeTest.verifyStakes(stakeDocs);

    //     bool success = bridgeTest.verifyHeader(
    //         verifierHeight,
    //         header,
    //         stakeDocs,
    //         signatures
    //     );

    //     assertTrue(success);
    // }

    function testVerifyHeadersMultiTx() public {
        bytes memory data = hex"0000000000000000000000000000000000000000000000000013b3d9187e38e5a3f295e773e4fb2ed565cdcf10c1134ef366c19507f4521f1286564bcd24022500000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000001c000000000000000000000000000000000000000000000000000000000000003c000000000000000000000000000000000000000000000000000000000000000fdff0fb4bb573cc995906576e965c43f24e339c407f6481242e25d0605702d5aca32fde6387e18d9b313005a400300ffd449143e0929da73227d8011585b10f6d0d75b92552b199462cfd5347a1fe039c54340a2d93d87bc014ef4223d85126c19f44cea17c411d52dfbda1f1cee56b7abbf8f5785b260c05762fd509df7257cd66c15776998c3d1817ab7febf87e2f3ff9af82c6bb5d41259c3f7ecfeeb3ebd677fbc685418da41b575a4a12cfe3cb0115d3031771bb6004c3fb1ceec638de45735507c478b97d7e817255c2cd53920c1aa2835c5e2e68d0e09ebb5483f76fba151c7e0a187533fbb1045a58809450b40d38771ae7bc524f9a8954763cd00000000000000000000000000000000000000000000000000000000000000000001ddfd9164353a03000000fd9164353a03000000261dfb4a2367c173877e513b254cfd95572a022067bb7bee2eed67abf94297edfc5934bb11fd5117ef21e978567ffc9db91391d376ab1f4134a295e32f580c3eff39de75cb2a1b74c8c9a00e70c3b9b61fa1b8fcd776eb35fd385ee28f4a307ebbfc169a4f0c3b4199b011a9e5c3799677f2e55c3310733815f86dfded2cd52af8f5ef937933fce9949c92fd2323693b1f473a1dfca41b20d99f1e17264c4f76a5822d874397c9ee1b414b5618c516c7d417b00be55c7b3f37fc845c4d1cfd2f7a7e008cf28de2fcb0564c1c300fc39e8511f2d38dbf7ab238b03613a756861226246dc4823b80e741800a04fca266285cfd915a27ecd4e8b19efcb1a8d9279d400b50136558323cc59ad8238b90a27056b0b2f0274dab7eab662eb9de49f5fcd948d06afd3289d99a6d67157afc04e1306d0247bc71da81d3447b3963cc22dc686881eda142fb58f260b6859ec8b66af0b3fce72d5d0ffd8438f6817bdb7751fcfbdc761da822f2df690c0a58690ba611f26f051473c27333a398913a5a890ed31b389e03fc5c87ae2ffd8514c8055893d9f6fc39595117213af4983f0863c466327a8ae7aefeac90e6510ac4852b031185b6f7f93f6b74fc3c36dd2afdf90c20035ea7c070fca1de92dd000000000000000000000000000000000000000000000000000000000000000000001280ed9290805db5687757e07295d91a9f3a90c7df48df978991d79f6b82101f37c90bbc7450a02886aee4725340c1477d1e73fc99b71c2f8f4afd03cc2c95cb0771efb64a8cb074eae4a392b004c21c900091a6178dbfdad282e2e79eceaf406ecaf0e4f0b28d797d30ce05aba06ae2c678829150394bee80887f0c01741ad90e402ff5b88dbad8c8fe09836fd1e9a37fab197cacc13c619cb86ec08a4d8d2fbf58cac8364771f1fde5cec53e689940fa434c2fda9bcc37138e75171681f5110123425a8d41e60f693c0d5169ab252ce519f9ef4d3193bcd89b404847f6c0f385fe1e76095af13088ae202f7372bc73c3417381a37fd208f06ab3ae322c773c06dc1a3907cbc071c6b7b08d5ed26c69214062baf88406febcff42ceb2563ec155abe03ee2ca8c18450a148e90a9ca784f9aa17711d84476e218989b08b6e78c0118b39dc2fc2c073e1f273d8799308373e0387e95abbd98b166f8b6f31ea923b832b2878b8ad1d22178aee081f1bd36fdfa0dfaaca4a16548267991689970d80d6c0d671a0e7fd0a67d431254f604f61c61f3771acc1a8cd3755344d22b2ca9fc3e82d7e95eca153c57417a8e005000c35589561c7ebf6716032eebc165e40203ccfdba1146d2c317c96727d887f7c90ee797fe24fd6de58b5187b45a8c2d23a96ebde0b40a61442953c2a33fcdb90cc3f9a5d509b9e59980008ffd83c267b90eaba3ca1b5dc6454f1dda0de24dc7e6544f424a07c89c34d369e352b88ae0d63306714ec69db838825cf10ee846c4e6e54a1a14e1845f9c58fbbcdea0dc389c0b";

        (
            uint256 verifierHeight,
            bytes32 verifierStakesHash,
            bytes memory header,
            bytes memory stakeDocs,
            bytes32[] memory signatures
        ) = abi.decode(data, (uint256, bytes32, bytes, bytes, bytes32[]));

        bridgeTest.verifyHeaderHelper{gas: 25_000_000}(verifierStakesHash, verifierHeight);

        bridgeTest.verifyStakes{gas: 25_000_000}(stakeDocs);

        bool success;

        while (!success) {
            success = bridgeTest.verifyHeader{gas: 25_000_000}(
                verifierHeight,
                header,
                stakeDocs,
                signatures
            );
        }

        assertTrue(success);
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

    function testVerifyTx() public {
        bytes memory data = hex"06ce98f3e4cc2aa771819b1d7d500105aae8be388f7ecd7bfb83e3d1a4e1f01d000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008507d03aab3eb59e0000000000000000000000000000000000000000000000000000000000000c6000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000057f3d2493f9bc5807cfdab4cd13054fd0000000000000000000000005bc1bf2c473165df2238c8fe18ad35bc38652a210000000000000000000000000000000000000000000000000000000000000b05510e60ce4756600da82eaa99661a144a0f34cbf1a2b67f9076508e09e003c18671c5b5a49f869fd8e7af7037421d1f1655870577f3814ed75b6b970cf21745221662c7e6041adb1e5e489d3927e1b18098cc432edd82a0cbbfab5fe18e664e84bd4f64b311538320cb90ea84cc2275700c37c1ffd1001f2d4a13c0dc733e240586dd94b4ea4bfc4fdc2a4a5f369de1ca125d93bc22a0310cc402f9eb383ecbff3c5738ed98a98a14c7efeed973104cbb496c88050b46982a7de0be08048fde3593704e6f1e2a99e10da56f76f46c2495a981c4f113462373363508b4effa0c8862f063adde54f07f6ee2371dd12bf6fec88f685f5a1fdf84d8c8688bd47521c0c079d2d6a865d56a30007148ee7a443cf5d10ebc877894099c57aea65c4b87182d0411e1569d14abde0bd371cd47b91a79cd79d84158ee0576d0bab20d67c3cec94894de1c09e9ffc3ab9f34cfe0d89b48959d52c59ae8d70774f4c298423a1d4660509cacb86f7a6368f481561ca328351fa670b13e06d6e9487d1cb7a5f80615235b74f28f53a7f634c455a5ba9b80e70d798ea2aae16bb5b340d058580ad9f0889d50a1bae76f5e7334704525cf1373d15277ca35473bdd1de537d56a0b0cf046d54127d2be37109f573d8530c82f190000000000000000000000000000000000000000000000000000000000000000fefd5430d14cabfd7c80c59b3f49d2f3570173145bc1bf2c473165df2238c8fe18ad35bc38652a216ab0660df5943ec0169becdb6e45d25a527410b78a63141ea5b15584165868d0fee255b69e79e3e5c74b871aa2ef4207f5016414473ff5d873f7962ac0647037d26c15afb18fddbae5e014f03214511d788c7c40fa21e1c210daf21ebaa0276f549b1124c76353d3fee1e1a082ae8fa915e68b255942beb62920307477148af56639bc428c9ccdaf8011e7aa336122e37a96d6af822794ac5bbb14494ec7c77e52f79e05a413b6f044cd48a26e1522ebb406090b7f847e50b9b11002eb601f8fb71f61fab28cf9ebb2d03113e960dbfeca595d01064e87a0f4545fd36a509a9b20dcd5ca24b7328d625e4609b58c513edc905fc21f5148851c81f45879e690406a14535f3c76a3a0a85e77cd570a021949fc85bc9e1364ee71b2081fed4cd694b57b378f584f4b8b2c0e4f36f5a0d2a46b5bc19bded7fe4babbad70fad0c86fa7723a6aa2819e4016d14df7ee8759a0c4ebd6fcf62d2d7c28a4515a1df5a63c14cfcb4e4c71f29c7b901dee255460fca18928316d8c701575df0366cd250fe466e390cc8070c5733871ca437e27ce820c385c95c7a39d39cd2e609ef9562baf9ee183b9bc9a5e120ffa48800427af56a1425509ff9043db8b39cce5c1c5f3bc9bb299a44c59696f51c8a2efad1ada0f7deb5e41c71f6ff8230b95fe2e82af05b30f9a0cf12fe2dbe07e0de65612f1a7d3f13f21ebdcf0173148a886c29ae66ea029dcb23afa19765104c80f6cba8e8eb0c88dd78f97ebcb4256ad69610f9e9513af1cbcbd4e5f64afb2b1fc804fee35d686420864ccc2aa5d8005e8c1a56016414ebff03cd18efae057c121666177cedffef9acd734cd25c5cc65021870ffbaa65fb22e1c01f6d65bd5a5cc3165a050da4c346a081fe1a90fa8c80fba1d93c08a0b98d3563bb017314701eaff2d59aa9471173d5a7e1e4cb54202da38fc6b6326074175477846558f16321a82d85f3ddc6c2155c4840bac8be31147718fe8d61ad270311d38410dda5a23ead3fb6016414b897e61ae19c8ac17a92c157c3c14a66bae4298b68f3e77bc0fde1716af82687eafd30a022a07fcc5aa8048c5668e77fe6505d0cfeb3f52ba13a3f463d782f19877350850c016d14966fc962b28f59958bf62c6404372784147ccc0b1c4cf90fc30082f67b4416a2d3295954c95cbea5dc82cb3708055a2d06a175fcfe093ddeee90bff35d7f5df1214fdab364016d140573e2bc7a4519515664b086dc4a21379e0afaee280dd2ecea598dd82c1c2a9f45d0998efeb6d7c204341ba6fcd6835169eef3d2fed9c53e076f1b5e6d87c21620bf92bab1016d1483d684c0d099f569cec53eb845c46535ce19a28cb35425d645ea10906132abfd3c3989fe16ce8c14df677db342aed5361f2dce35fe02eedecca2114ce1a31ffe9fb818787f017314c24c34dd1100c233615e0a2550f99567ddeeb813db0ccbe19e8d6d63a6c19984efc5ed5ecf9ce2087d731b7df35ca071caab17c3fecd2d8f49bcdffaeef7de96a72a0ced4901731485a05cbaa21dbbbc6b335ad60a2d493d0daa1b372b32df345d5c12721b38dbd93d581969bd960ce6fd5ca60ea869c0bf3c7ff1affeac440e0f0ae873c9ffa0272e65ecf341017314d7a61aa8bfc16069ab3987b54266524595d3e955427db21fad161dcd3d60d1cd24e01456650440c0b443e9b7195420a96e01ff94fe01878d44cd7d63600384074a16a6b85a016d1403eb953e3ef2ce6813c1b966bf751e357cb6235be7e168f9e41c8a1284f245c746b6321684d2f3d338bf453280b214984fc7316ffec302503c22fe0e798cbc2e20a80b402d016d144ae7f4c63e85e5ed01ab4b35de1bb4d19db84052de1efed65f63289b2bc831ed39ef707add78149f3b49cf698b749466ac481411fe31eedad65ce8e01b68df5aa05d4c1dc0016d14848bd6c5f2cc77a9d6bd17d84db9472223d7e11d2f93f71491c7f87805d4c2058ac6fa384192144ee713ef4d3311ad55a4fd2383fefabd0e5f4b69a0fe48c26f953924bfe2205329d14c19af72f1491d8abec8233a97889b6f7cf3346a7bf716901f77704f3f147b685ccfbe5bdb3f4b44a865fd8b3875ebae650e91f3658dc92e8804829de885ef2cfe751aab97253acc6c425ec8423103670a4afec74fc5133d00d006de452485f430d4d220c137532064216e1792a83cbedcd83a10830eeab11795f8abb772f511cd04ee66144e59647e8beb9ef384188b3e97a8a9df1fba480d8f8b1cb39b036df1fc2cc13e0692eb7c6e2a3f6c8bfd0737639ed5b83959151afe2f6242c049d90746cb400fd6a6f00cc40173149282d382fba00f404b238fe70ad3685ac79ff101973c69ab7d5cebf476bf600094d5a14a2598bece867979f0987673ff58c7aa0afe7a957aaa09339cc5daadc4eed3c0e5e0016d14d598c1f977fd7181ba9a5edae1a7022f80838d3f375068373e9de79fc3eb6112f887d2963289b38dbde4901a4e5fd3271cebade4fe5cebd5cc1dd6570f1d736bead4315378203cc8f350a4322ed7e338e57b83cb381cdc6180f16ef65933327de3d2213fc73914bdf2e248aae45f05d739be9cc4ac71b3a17b7ef64e87b14e9352814811202a2ca6860be3f183265f9472cb32888d0ca1235409d5fee15c451b31f3abd7409523c6d65f89fb016414cd9636a20d05da60542cc589c2088b25d8ae4f72fef9111183da0c08a78c1344c5b5a38251021752dcba9c540548796f6bf7ed012d39fbbc66af3da5203f13d32dbbe760a3e5cfdcab828fee31d7fcae6727028761121e8db4e4e2c0ecdc6970e6de8ccb6372a01c811e941e9b01d08f308b1ed74b1dd8b0303ccaf2d1a5d18009a1bc8fbea82e88d481b4befc25d70d917a491877c478dc07157ef82bae0555cb7dc0cd88fbfd02b30fefe113d64cdb0b24e5d4e8479833cdf861401a5f98140aa96240cdb23895ae6983056da2652dd1178f130040ebc477d9c0ca0cf2450d59e880f9c742308e7c0d3b4b7d28e7907a2c9fca01f7ed1a657f536e1cdbf806624dd429245b3368a0579539b81040a093d60005532635fe2105a8c0c664ac0cfc9fa7a5b6d57ea69b3612780f88ba241b64b507a3b36729ebcacd0b082b2f8c7cef34b0411fe971144616558f2e06b87cc774eb3284d88a33f93a82ef3bb011c27c9e569106b6c431bceb7a194bbe35d99d960e564047faa69213c48b4f59e0a4ed588ee56000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002f8ec7c82ed3b27af595208fc8c81f7c48dc1fa9dc5ef01f1f58c4c275e24eb5bda386f69440cc2de10283ed5755ff931a31df9312028a08bcf4b17d0fbcae362";

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

        address logic = address(implementation);
        bytes memory data = abi.encode(
            bytes4(keccak256('initialize(uint256,bytes32,bytes32)')),
            0,
            0,
            0
        );

        ThemelioBridgeProxy proxy = new ThemelioBridgeProxy(logic, data);

        string memory uri = IThemelioBridge(address(proxy)).uri(0);

        assertEq(uri, 'https://melscan.themelio.org/{id}.json');
    }
}