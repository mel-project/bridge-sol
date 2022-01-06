// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.10;

import 'ds-test/test.sol';
import 'blake3-sol/Blake3Sol.sol';
import '../lib/Utils.sol';

contract ThemelioBridge is DSTest {
    using Utils for bytes;

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

    string ERR_MERKLE_PROOF = 'Invalid Merkle proof structure';

    function computeMerkleRoot(
        bytes32 txHash,
        uint256 txIndex,
        bytes memory proof
    ) public /**internal view*/ returns (bytes32) {
        if(proof.length == 32) return bytes32(proof);

        require(proof.length > 64 && (proof.length & (proof.length - 1) == 0), ERR_MERKLE_PROOF);

        Hasher memory hasher = blake3.new_hasher();
        Hasher memory hasherUpdate;
        bytes32 metaHash = txHash;

        for(uint256 i = 1; i < proof.length / 32; i++) {
            if(txIndex % 2 == 1) {
                hasherUpdate = blake3.update_hasher(
                    hasher, abi.encodePacked(proof.slice(i * 32, 32), metaHash)
                );
                metaHash = bytes32(blake3.finalize(hasherUpdate));
            } else {
                hasherUpdate = blake3.update_hasher(
                    hasher, abi.encodePacked(metaHash, proof.slice(i * 32, 32))
                );
                metaHash = bytes32(blake3.finalize(hasherUpdate));
            }
            txIndex /= 2;
        }
        return metaHash;
    }

    function verifyTx(
        bytes calldata rawTx,
        uint256 txIndex,
        uint256 blockHeight,
        bytes calldata proof
    ) external /**view*/ returns (bool) {  
        Header memory header = _headers[blockHeight];
        bytes32 merkleRoot = header.transactionsHash;
        Hasher memory hasher = blake3.new_hasher();
        Hasher memory hasherUpdate = blake3.update_hasher(hasher, rawTx);
        bytes32 txHash = bytes32(blake3.finalize(hasherUpdate));

        if(computeMerkleRoot(txHash, txIndex, proof) == merkleRoot) {
            emit TxVerified(txHash, blockHeight);
            return true;
        } else {
            return false;
        }
    }
}
