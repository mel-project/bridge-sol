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
            txHash = string(ByteStrings._slice(abi.encodePacked(txHash), 2, 64));

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

    function verifyStakesHelper(bytes32 key) public view returns (bytes32) {
        bytes32 stakesHash = stakesHashes[key];

        return stakesHash;
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

    function testKeccakBigHashFFI() public {
        string[] memory cmds = new string[](2);
        cmds[0] = './src/test/differentials/target/debug/bridge_differential_tests';
        cmds[1] = '--big-hash';

        bytes memory packedData = vm.ffi(cmds);
        (bytes memory data,) = abi.decode(packedData, (bytes, bytes32));

        keccak256(data);
    }

    // function testSliceDifferentialFFI(bytes memory data, uint8 offset, int8 length) public {
    //     uint256 dataLength = data.length;

    //     if (length < 0) {
    //         vm.assume(offset + length >= 0);
    //     } else {
    //         vm.assume(offset + length <= dataLength);
    //     }

    //     string[] memory cmds = new string[](7);

    //     cmds[0] = './src/test/differentials/target/debug/bridge_differential_tests';
    //     cmds[1] = '--slice';
    //     cmds[2] = data.toHexString();
    //     cmds[3] = '--start';
    //     cmds[4] = uint256(start).toString();
    //     cmds[5] = '--end';
    //     cmds[6] = uint256(end).toString();

    //     bytes memory result = vm.ffi(cmds);

    //     bytes memory slice = _slice(data, start, end);

    //     assertEq(slice, result);
    // }
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
        cmds[0] = './src/test/differentials/target/debug/bridge_differential_tests';
        cmds[1] = '--big-hash';

        bytes memory packedData = vm.ffi(cmds);
        (bytes memory data, bytes32 dataHash) = abi.decode(packedData, (bytes, bytes32));

        bytes32 bigHash = bridgeTest.hashDatablockHelper(data);

        assertEq(bigHash, dataHash);
    }

    function testDecodeHeaderFFI(uint128 mod) public {
        string[] memory cmds = new string[](3);

        cmds[0] = './src/test/differentials/target/debug/bridge_differential_tests';
        cmds[1] = '--decode-header';
        cmds[2] = uint256(mod).toString();

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
        string[] memory cmds = new string[](3);

        cmds[0] = './src/test/differentials/target/debug/bridge_differential_tests';
        cmds[1] = '--decode-integer';
        cmds[2] = uint256(integer).toString();

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
        string[] memory cmds = new string[](9);

        cmds[0] = './src/test/differentials/target/debug/bridge_differential_tests';
        cmds[1] = '--decode-transaction';
        cmds[2] = abi.encodePacked(covhash).toHexString();
        cmds[3] = '--value';
        cmds[4] = uint256(value).toString();
        cmds[5] = '--denom';
        cmds[6] = bridgeTest.denomToStringHelper(denom);
        cmds[7] = '--recipient';
        cmds[8] = abi.encodePacked(recipient).toHexString();

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

// [FAIL. Reason: EvmError: Revert. Counterexample: calldata=0x40559ef2000000000000000000000000000000000000000000000000000000000000001c, args=[28]] testVerifyHeaderDifferentialFFI(uint8) (runs: 47, μ: 14221186, ~: 5619337)
// Traces:
//   [31617887] ThemelioBridgeTestInternalCalldataFFI::testVerifyHeaderDifferentialFFI(28)
//     ├─ [0] VM::assume(true)
//     │   └─ ← ()
//     ├─ [0] VM::ffi(["./src/test/differentials/target/debug/bridge_differential_tests", "--verify-header", "28"])
//     │   └─ ← 0x000000000000000000000000000000000000000000000000000988edc25a3d169d75b03b8a3994d48bd9b0a63824df274f6425964c16ba7653c8b136dc2c870900000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000001c000000000000000000000000000000000000000000000000000000000000007a000000000000000000000000000000000000000000000000000000000000000fdffb7c2d6aafeb551396367a54eae8f1375dc187c8687adde39728f9ea60d10eab3fd173d5ac2ed880900ed389810926ae0b8f7245e3c525b4725b0effb07733e7f4ca0a728477248b9ee9c83aa2a199367398ea4652a5dcda55ab8aff942c740b0f89a3144f395642bd91016ba6dbd27e5219a141ed5de5b9bdcf6bcc11d04ee76ffb24006c08e39b7aefe9b59ec1eba96bda8001b235102be0018fea037580b4e1992b4b04daf79831a00d1fe50f91b3c03aa8cf7ce1c8c67e37982259753de35b734c6c2a38398f2a2b6f1fc3b65e69e455bd4fba4c6a8d09ec1cb7ba24cbc5cb2d817a399108628657b0dd71256bbf3072e5e5ffde11568a565bf0f00000000000000000000000000000000000000000000000000000000000000000005a6fd86c4f7ea0d000000fd86c4f7ea0d00000044e0ab6e9c69cd2e542e9b8bf263f2130e2c6cb14522ab35496795416efeadbcfcd970ec2cfdfb27f724a300b11efc110082c6cbdc8f0082ded16fa9349146c616dd3c0366a152e8d22522b57aa2bf788baf5cfc310bd302fdfd6a59b684f47895fc6b08ef437ef234841c531d1d4197678e4c2e371d08866699219eb395b1c1cff187edbe5efc1e2bcd30fd0b0232363aba2661fc99f06390c44a37d1c645101d3e2e4c52dee802b5fdad1bffcfaaf2931919c224e72b2cf3fcbeae3735fd54b5edf979afd807fcdaeee3d8554e88be65bafdd6390bff5ade1f5dcb9d794b781ecea21f0a22ba8458123793fc99a4863cfda7410acae292810afc0eea54504d24e557018f23c3906097f6f19e76d5ce7e5a4a690f6bb18d65c66717aa93adfc4d763f03fd010ef99e517f8a8bfce62812db5f7dfe0ef4a708869d502400b9dead7b73d46fdc719f090f843ad5b7de0ee71efc8450dc02fd4685c18e4f781315fcc7d8db2c5f8875373802c7486554d96a8f9b94d2c5dc73b9d6beb593834ad684c8b4df03fc1864d91efd3d0ef9bae3e8f5befcb1d8bf8450466b51e8df65b159e9bb6d9ee70d835f7474ebaca25030f6621c97aa771451fcc954d20ffd5216970c0c223c9efc15068de5629aa8f46fcc818d69fae0517ada7196ed56a2ec103edb22dd05addf40c3c7d2fcbd1a0b4bfd0bb67550fbceacacfc7fe7ef11d5b7bbf8e1bfbb701bca26200e17411d629d660bda7a9b17065d433cd54067b3fcce38374cfd6d2efe87dc3111b9fc387e6809f188c0f981495fa290367139461808bb17b71948ce96154b00ffc99c7fff74b4fca1a5a320fd9ee48e0e8c9fef30fcacfe87ba6725ed060051b4374f7cf057199fc7ac5f1180d91ac79d0c2763274f63f81b81fcfec8b42bfd77bc3b435bec3e5efc536b821dc0aa9bab2bae89422c9642fecda7bc4221908a7687addb36f607b2f1fbef5f25fcabdfac44fde87fdb9247f5da75fc9d544e38d31e18e2d53dd9419683a2da8699d3bc5b43d22cf477224a5d210b304b9fefebfc85f4a006fdc541c409bc96944afc44af479e4d2b1ebc7beac19004f45aae1fb67d9cfb99f1c7d7fd4f0d57b856b995445168fc00782d09fdba1f27b24bfd999cfcd79802e4eb7da7db7e87a340dcb92a56d2bda5caff5fdc5b363854e9d09086a139253111fcbb99c83dfd341c44f6a1e596a9fc67314cef1286666559166990706d583adab988c20a14ae498a8f56565b7212ff0a9dcf4bfc3a364e35fd15747f814fbc47e7fc35a847828fc4b98ead9a91141b52737d571450c87fcd18beeaebcf2d2aa7cab1c23d71e3fcb3bba81afd594a2d1cfcabd8d2fc4b5679a5b9f18d5df3e7d3f1a7271641e1b3e1419dec1a2e93551416d144495cfebf5008fcb598fa14fd97c1c1d18aa1cb05fc90626dc5fc27ddbba385f4f7328e0808e36b18e1c330de44ec6d6e0370871d7ec10f55c8fcef2a1c2dfd97f660e7828d2c96fc24df7f952f111948054326c1d36a189081c09623b9683e71beda731e78d1a2771661dfbbfc3609131dfd501eb950e1e3f47dfc20da6f7ddd40559fd8de13d1a46af144816f2460367342d0e865e9e9f52edef4dfa0a311fc8f2cbf24fdabca8dfab92a2b67fc5d107919ccf740bf1e939938f2307c8dd87032ae6032681dcf13c7c24345e25aca4ee14bfcdb26de2efd6d1f560d227955fcfcaf32da40649d83146c4752fd1f4bbdd7b0a5c3a3795f71ceccc576f2fa3f9c3ba52440e7fcaf2ee54bfdef73521837e9d70bfc78bab35498721d4a7d49739084d31ef8b9b0787180e9f752fb4eadf7e4542d3b126aeefcfc3e431334fd35eb96aa818e340afc5ad383c37ff792ccf41d01f13123889bef8ec5a8ef5d517608d57d89150eae610f5e65e5fc12779c4efd3a0b07fcfd371804fccf3bf35f8262388df2b650f621e2eaf29c33d6b02094f3b6e6fa9689e5a0c649a2ed1470fcb192710cfd1da36cafa6b688dbfc404dcb4400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000038952265c8017a19c6c96d419b9891bad20ce3e03f349cb92f5ef90d77e52825dfa57b7f7e0c4b2ff6da63f45d836d52f63a9149e066f6c6ef58c458da74ef12085f6c52705caa27d6151df30841e026694ccad3f8d6817025f244f84a13f495b4d8a669e15613c978f24af78951a9887b3278141a15da24bedb57b4963bd3d10b5ad3e33dbcafc9301a8baf32fc898b696e7c59c677492f674a5902d288bef92ece494f7ff58c751b325c0e5f7b8153df5ea36a93bfe453addc488cfc0f915e00e9b3d4e6a947c5ab020c75bed916588a5062261c0359724f74cc6801850544d869f02ab189d49d2aa12d46b6f3074d7aa834cb7542c11452b8b13d284cc42c0a503cc175c56d22228eb9ed831dd76717a4a86b7404f60f8f8966e423d1576d6e3b9293497b221fc5e009b875a163beddfa0df603eef3ef316c7a515addb27308395593902504d425384b905e7a2fb864df10991d6113e862784df651fdd430e19aa2a8e728811e060bec8cf665fa15293f08a1e943bc183dca5d4205cf85a00a0d2f63b24d9f881f44bf270ed68f010810cd964bc1ec7fa3242be9711d04f2e72c844dc2a77c81bdabfa69244084073ea320e0007bce4bd9604bebda8fe6a80dfc917dd21e6c37bad322d565f5df756f60a6a8d338d9318ce1cd4eed0f7f4e982a36d55660cde00994c68ed9f8105d2d445046b16b4d0e8dc6947f4e13f1dd0f9dc420c6e9aadca91adb8ffa8a0ec829e7e0a6739c94d0a6207501b996a7154ffeffb396d2722a41fd975b0764ef337ad6ed90467e4285920a384d5698524100ebf62cef8f06632fdd882b13ccea5b8b34f7f8f8180c30be84c87a484e11913c5539190d98148c6a1d7db973a087ae76b449b49e3ef3a7b49182abb10a99470879a9ec2819c8aa120e5c18be74ea0e25b3df8eb12c7af750fdb9f3682fa847a0e5f0b5bb829e4fc4cbc3cfc9ed55da1e4de3793fb60a6f4c7abdb78283ca4904164895d6a53d05943d82576175d241d89c0129b60cf8338aae29df7e0f11aaf2ec15cedbddc08cfbe7e09547d7a3058e2363cc53d55d68c566db1b8b42d29b0375da9b898729eead108802c679827a02b9d07b7a1e634d6d81199581212272c2c053a2450717a5b54462b0e87fa939824a3b97a66dac36e695881b512a735b0fcd002d50133f0e1067da9274b3dc8ed5098aaf30f161ed18d0dbc9998110d27e3aad80c0a009d8b91c49c5b53241e17cceda15493c8d60c7a775742d742e2c0523ec4beb28b3e312c5788cd652b5320e54d7a4ff1e8312cda475c677988cb4f52c3a985eedab136ef0f474435ff3a7e0e09194d01981d1e8b9d7c5638bf92d0e9e0b9962ab827b408a1ba230387fed7c75fda75db5992a2c6fcc04cafc45def944b003917198e5e21c60a7744662e48c314e5f67a4b23b27c2f6df0eac83640eadbb8cfcdaec7ca593f82cb6d1356b513613f588f937d97cbfa370182683435735b992f2ba44719bc2de25eeeedeef2635b3e7fa02a5f095f0168666e22aa20a0739920b95af7bb911015f90fda4cdec790489d90065cc79a3790d46e911c3fdba678274e85c033df4f54b791a0008c983d49b86f5f345ac6e309f1f60983f021b14e575ec86ef3cae1485192baf9fc7e0a26948d2e50b745d8145c32e2674ba6b1fb2358c73b09c0b90c7a93bea6fa673dde0668eec24ae042410ae9887e90bf4512525229bf66b33be87e83fedbab22ce439f1ecdfcd21ab9f99e33ea9a588df969c2acfb00723e571fa0e6fd74dbb809bea94fad50e2f7493daa7448b710da42a587601bb29382b7fa6608c5205a850a990e56e9ea1110fb2796f2463e1baf8b63636f0d5c1f892a4f2c74de47654f539cfb746e0ff18c3f65ace13d2bd0ae3163623dfbbb25aa37c1c28ff088aabd250af37e6754c132769e79d752ae0a7247c349c92db6f90318140fc8a4679212b9fdb2d2059654f449e31dc56236400ed5b6ebbbd66f7fa05b6676d2ac3e3ec91dae33fca9fc1b1f562bd7ff7341d0c849fb112fc384b0df1c165db355dc78e87940946b6c98007aa9b405fdbb379033cdd980be2c1000a1c9275446f62a676a98269e750e63c6fa04939be06a0d4a61a62b0dd65bba6f25550fdae0265189b4cfbd7b946b2faa0afeee9fbc40a780ef5e01013919228c51919ad8a87b247732d01a3d0dc7e9f62b17838831096d2fba8556896cc8617fb6425870853abaa873b4824bae860d3a1db5a6c74b014b90486b188c979537aec7dabe0444781c8f68a0945f1b9762e7f3b9dd371135f1fdc20867affe038b44d0d4c433a90278385fc722f432236fff6e74d62fdf3fd5a055a9550db670f5d63a3593e9f446127427f414a4dac48b9a6a4d1a6617243c274d11383aa8d2997c56a61fa8774b800eed6771fe303a9694e0f8a260e21e4470d5e6f2a08b34d10c6320b25c5933eb45b135de2e192fe1c44c9ef3aba1d09167ead0fc9bbec187a6c54bcb6d18709b1d15edb08ea23d25254d4ce5071aba5ef09
//     ├─ [22904] ThemelioBridgeTestFFI::verifyHeaderHelper(0x9d75b03b8a3994d48bd9b0a63824df274f6425964c16ba7653c8b136dc2c8709, 2683829539716374)
    function testVerifyHeaderDifferentialFFI(uint8 numStakeDocs) public {
        vm.assume(numStakeDocs != 0 && numStakeDocs < 100);

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

    function testVerifyStakesDifferentialFFI() public {
        uint256 numStakeDocs = 5;

        string[] memory cmds = new string[](3);
        cmds[0] = './src/test/differentials/target/debug/bridge_differential_tests';
        cmds[1] = '--verify-stakes';
        cmds[2] = numStakeDocs.toString();

        bytes memory data = vm.ffi(cmds);

        (
            bytes memory stakes,
            bytes32 stakesHash
        ) = abi.decode(data, (bytes, bytes32));

        bridgeTest.verifyStakes(stakes);

        bytes32 savedStakesHashKey = keccak256(stakes);
        bytes32 savedStakesHash = bridgeTest.verifyStakesHelper(savedStakesHashKey);

        assertEq(savedStakesHash, stakesHash);
    }

    function testVerifyTransactionDifferentialFFI() public {}

    function testVerifyHeaderCrossEpoch() public {}

    function testVerifyHeaderNotEnoughSignatures() public {}
}