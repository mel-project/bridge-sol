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
    }

    Blake3Sol blake3 = new Blake3Sol();

    mapping(uint256 => Header) private _headers;

    event TxVerified(bytes32 indexed txHash, uint256 indexed blockHeight);

    bytes13 private constant DATA_BLOCK_HASH_KEY = 0x736D745F64617461626C6F636B; // 'smt_datablock';
    bytes8 private constant NODE_HASH_KEY = 0x736D745F6E6F6465; // 'smt_node';

    string private constant ERR_MERKLE_PROOF = 'Invalid Merkle proof structure';

    function computeMerkleRoot(
        bytes32 txHash,
        bytes32[] memory proof
    ) public /**internal view*/ returns (bytes32) {
        require(proof.length == 256, ERR_MERKLE_PROOF);

        Hasher memory hasher = blake3.new_hasher();
        Hasher memory hasherUpdate;
        bytes32 metaHash = txHash;

        for(uint256 i = 0; i < 256; i++) {
            if((txHash >> i) & bytes32(uint256(1)) == 0) {
                hasherUpdate = blake3.update_hasher(
                    hasher, abi.encodePacked(NODE_HASH_KEY, metaHash, proof[i])
                );
                metaHash = bytes32(blake3.finalize(hasherUpdate));
            } else {
                hasherUpdate = blake3.update_hasher(
                    hasher, abi.encodePacked(NODE_HASH_KEY, proof[i], metaHash)
                );
                metaHash = bytes32(blake3.finalize(hasherUpdate));
            }
        }
        return metaHash;
    }

    function verifyTx(
        bytes calldata rawTx,
        uint256 blockHeight,
        bytes32[] calldata proof
    ) external /**view*/ returns (bool) {  
        Header memory header = _headers[blockHeight];
        bytes32 merkleRoot = header.transactionsHash;
        Hasher memory hasher = blake3.new_hasher();
        Hasher memory hasherUpdate = blake3.update_hasher(hasher, abi.encodePacked(DATA_BLOCK_HASH_KEY, rawTx));
        bytes32 txHash = bytes32(blake3.finalize(hasherUpdate));

        if(computeMerkleRoot(txHash, proof) == merkleRoot) {
            emit TxVerified(txHash, blockHeight);
            return true;
        } else {
            return false;
        }
    }
}
