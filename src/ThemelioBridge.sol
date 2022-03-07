// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.10;

import 'ds-test/test.sol';
import 'blake3-sol/Blake3Sol.sol';
import 'ed25519-sol/Ed25519.sol';

contract ThemelioBridge is DSTest {
    struct EpochInfo {
        uint256 stakedSyms;
        mapping(bytes32 => uint256) stakers;
    }

    Blake3Sol blake3 = new Blake3Sol();

    mapping(uint256 => bytes) public headers;
    mapping(uint256 => EpochInfo) public epochs;

    event HeaderRelayed(uint256 indexed height);
    event TxVerified(bytes32 indexed txHash, uint256 indexed height);

    bytes32 private immutable DATA_BLOCK_HASH_KEY;
    bytes32 private immutable NODE_HASH_KEY;

    string private constant ERR_ALREADY_RELAYED = 'Block already relayed';
    string private constant ERR_INSUFFICIENT_SIGNATURES = 'Insufficient signatures, need >2/3 of total stake represented.';
    string private constant ERR_INVALID_SIGNATURES = 'Signatures are improperly formatted.';

    constructor() {
        Hasher memory nodeHasher = blake3.new_hasher();
        nodeHasher = blake3.update_hasher(nodeHasher, 'smt_node');
        NODE_HASH_KEY = bytes32(blake3.finalize(nodeHasher));

        Hasher memory leafHasher = blake3.new_hasher();
        leafHasher = blake3.update_hasher(leafHasher, 'smt_datablock');
        DATA_BLOCK_HASH_KEY = bytes32(blake3.finalize(leafHasher));
    }

    function hashLeaf(bytes memory leaf) internal returns (bytes32) {
        Hasher memory hasher = blake3.new_keyed(abi.encodePacked(DATA_BLOCK_HASH_KEY));
        hasher = blake3.update_hasher(hasher, leaf);

        return bytes32(blake3.finalize(hasher));
    }

    function hashNodes(bytes memory nodes) internal returns (bytes32) {
        Hasher memory hasher = blake3.new_keyed(abi.encodePacked(NODE_HASH_KEY));
        hasher = blake3.update_hasher(hasher, nodes);

        return bytes32(blake3.finalize(hasher));
    }

    function slice(uint256 start, uint256 end, bytes memory data) internal pure returns (bytes memory) {
        bytes memory dataSlice = new bytes(end - start + 1);

        for (uint256 i = 0; i < (end - start + 1); i++) {
            dataSlice[i] = data[i + start - 1];
        }

        return dataSlice;
    }

    function extractMerkleRoot(bytes memory header) internal pure returns (bytes32) {
        bytes1 heightLengthByte = bytes1(slice(32, 34, header));
        bytes32 merkleRoot;

        if(heightLengthByte < 0xfb) {
            merkleRoot = bytes32(slice(34, 98, header));
            return merkleRoot;
        } else if (heightLengthByte == 0xfb) {
            merkleRoot = bytes32(slice(38, 102, header));
            return merkleRoot;
        } else if (heightLengthByte == 0xfc) {
            merkleRoot = bytes32(slice(42, 106, header));
            return merkleRoot;
        } else if (heightLengthByte == 0xfd) {
            merkleRoot = bytes32(slice(50, 114, header));
            return merkleRoot;
        } else if (heightLengthByte == 0xfe) {
            merkleRoot = bytes32(slice(66, 130, header));
            return merkleRoot;
        } else {
            assert(false);
            return merkleRoot;
        }
    }

    function extractBlockHeight(bytes calldata header) internal pure returns (uint256) {
        bytes1 heightLengthByte = bytes1(header[32:34]);
        uint256 blockHeight;

        if(heightLengthByte < 0xfb) {
            blockHeight = uint8(heightLengthByte);
            return blockHeight;
        } else if (heightLengthByte == 0xfb) {
            blockHeight = uint16(bytes2(header[34:38]));
            return blockHeight;
        } else if (heightLengthByte == 0xfc) {
            blockHeight = uint32(bytes4(header[34:42]));
            return blockHeight;
        } else if (heightLengthByte == 0xfd) {
            blockHeight = uint64(bytes8(header[34:50]));
            return blockHeight;
        } else if (heightLengthByte == 0xfe) {
            blockHeight = uint128(bytes16(header[34:66]));
            return blockHeight;
        } else {
            assert(false);
            return blockHeight;
        }
    }

    function extractSender(bytes memory transaction) internal pure returns (address) {

    }

    function relayHeader(
        bytes calldata header,
        bytes32[] calldata signers,
        bytes calldata signatures
    ) external {
        require(signatures.length % 64 == 0, ERR_INVALID_SIGNATURES);

        uint256 blockHeight = extractBlockHeight(header);
        require(headers[blockHeight].length == 0, ERR_ALREADY_RELAYED);

        uint256 epochSyms = epochs[blockHeight / 100000].stakedSyms;
        uint256 totalSignerSyms = 0;
        uint256 signerSyms;

        for(uint256 i = 0; i < signers.length; i++) {
            signerSyms = epochs[blockHeight / 100000].stakers[signers[i]];

            if(signerSyms > 0 && Ed25519.verify(
                    signers[i],
                    bytes32(signatures[i * 64:(i * 64) + 32]),
                    bytes32(signatures[(i * 64) + 32:(i * 64) + 64]),
                    header
            )) {
                totalSignerSyms += signerSyms;
            }
        }

        require(totalSignerSyms > ((epochSyms * 2) / 3), ERR_INSUFFICIENT_SIGNATURES);
        headers[blockHeight] = header;
        emit HeaderRelayed(blockHeight);
    }

    function computeMerkleRoot(
        bytes32 txHash,
        uint256 txIndex,
        bytes32[] calldata proof
    ) internal returns (bytes32) {
        bytes32 root = txHash;
        bytes memory nodes;

        for(uint256 i = 0; i < proof.length; i++) {
            if(txIndex % 2 == 0) {
                nodes = abi.encodePacked(root, proof[i]);
            } else {
                nodes = abi.encodePacked(proof[i], root);
            }
            txIndex /= 2;
            root = hashNodes(nodes);
        }
        return root;
    }

    function verifyTx(
        bytes calldata rawTx,
        uint256 txIndex,
        uint256 blockHeight,
        bytes32[] calldata proof
    ) external returns (bool) {
        bytes memory header = headers[blockHeight];
        bytes32 merkleRoot = extractMerkleRoot(header);
        bytes32 txHash = hashLeaf(rawTx);

        if(computeMerkleRoot(txHash, txIndex, proof) == merkleRoot) {
            emit TxVerified(txHash, blockHeight);
            return true;
        } else {
            return false;
        }
    }
}
