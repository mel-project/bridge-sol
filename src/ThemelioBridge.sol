// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.10;

import 'ds-test/test.sol';
import 'blake3-sol/Blake3Sol.sol'; 

contract ThemelioBridge is DSTest {
    struct Header {
        bytes1 netId;
        bytes32 previous;
        uint64 height;
        bytes32 historyHash;
        bytes32 coinsHash;
        bytes32 transactionsHash;
        uint128 feePool;
        uint128 feeMultiplier;
        uint128 doscSpeed;
        bytes32 poolsHash;
        bytes32 stakeDocHash;
        address relayer;
    }

    Blake3Sol blake3 = new Blake3Sol();

    mapping(uint256 => Header) public headers;

    event HeaderRelayed(uint256 indexed height);
    event TxVerified(bytes32 indexed txHash, uint256 indexed height);

    bytes32 private immutable DATA_BLOCK_HASH_KEY;
    bytes32 private immutable NODE_HASH_KEY;

    string private constant ERR_ALREADY_RELAYED = 'Block already relayed';

    constructor() {
        Hasher memory nodeHasher = blake3.new_hasher();
        nodeHasher = blake3.update_hasher(nodeHasher, 'smt_node');
        NODE_HASH_KEY = bytes32(blake3.finalize(nodeHasher));

        Hasher memory leafHasher = blake3.new_hasher();
        leafHasher = blake3.update_hasher(leafHasher, 'smt_datablock');
        DATA_BLOCK_HASH_KEY = bytes32(blake3.finalize(leafHasher));
    }

    function hashLeaf(bytes memory leaf) public /**view*/ returns (bytes32) {
        Hasher memory hasher = blake3.new_keyed(abi.encodePacked(DATA_BLOCK_HASH_KEY));
        hasher = blake3.update_hasher(hasher, leaf);

        return bytes32(blake3.finalize(hasher));
    }

    function hashNodes(bytes memory nodes) public /**view*/ returns (bytes32) {
        Hasher memory hasher = blake3.new_keyed(abi.encodePacked(NODE_HASH_KEY));
        hasher = blake3.update_hasher(hasher, nodes);

        return bytes32(blake3.finalize(hasher));
    }

    function relayHeader(Header calldata header) external returns (bool) {
        // confirm that header has >2/3 validator signatures

        require(headers[header.height].relayer == address(0), ERR_ALREADY_RELAYED);
        headers[header.height] = header;

        emit HeaderRelayed(header.height);
        return true;
    }

    function computeMerkleRoot(
        bytes32 txHash,
        uint256 txIndex,
        bytes32[] calldata proof
    ) public /**internal pure*/ returns (bytes32) {
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
    ) external /**view*/ returns (bool) {
        Header memory header = headers[blockHeight];
        bytes32 merkleRoot = header.transactionsHash;
        bytes32 txHash = hashLeaf(rawTx);

        if(computeMerkleRoot(txHash, txIndex, proof) == merkleRoot) {
            emit TxVerified(txHash, blockHeight);
            return true;
        } else {
            return false;
        }
    }
}
