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

    mapping(uint256 => bytes) public headers;
    mapping(uint256 => EpochInfo) public epochs;

    event HeaderRelayed(uint256 indexed height);
    event TxVerified(bytes32 indexed txHash, uint256 indexed height);

    bytes32 private immutable DATA_BLOCK_HASH_KEY;
    bytes32 private immutable NODE_HASH_KEY;

    string private constant ERR_ALREADY_RELAYED = 'Block already relayed.';
    string private constant ERR_INSUFFICIENT_SIGNATURES = 'Insufficient signatures.';
    string private constant ERR_INVALID_SIGNATURES = 'Improperly formatted signatures.';
    string private constant ERR_OUT_OF_BOUNDS = 'Out of bounds slice.';
    string private constant ERR_INVALID_SLICE_ARGS = 'Invalid slice arguments.';

    Blake3Sol blake3 = new Blake3Sol();

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

    function slice(bytes memory data, uint256 start, uint256 end) internal pure returns (bytes memory) {
        require(start <= end, ERR_INVALID_SLICE_ARGS);
        require(data.length >= end, ERR_OUT_OF_BOUNDS);

        bytes memory dataSlice = new bytes(end - start);

        for (uint256 i = 0; i < (end - start); ++i) {
            dataSlice[i] = data[i + start];
        }

        return dataSlice;
    }

    function decodeInteger(bytes calldata data, uint256 offset) internal pure returns (uint256) {
        bytes1 lengthByte = bytes1(data[offset:offset + 1]);
        uint256 integer;

        if(lengthByte < 0xfb) {
            integer = uint8(lengthByte);

            return integer;
        } else if (lengthByte == 0xfb) {
            integer = uint16(bytes2(data[offset + 1:offset + 3]));

            return integer;
        } else if (lengthByte == 0xfc) {
            integer = uint32(bytes4(data[offset + 1:offset + 5]));

            return integer;
        } else if (lengthByte == 0xfd) {
            integer = uint64(bytes8(data[offset + 1:offset + 9]));

            return integer;
        } else if (lengthByte == 0xfe) {
            integer = uint128(bytes16(data[offset + 1:offset + 17]));

            return integer;
        } else {
            assert(false);

            return integer;
        }
    }

    function encodedIntegerSize(bytes memory data, uint256 offset) internal pure returns (uint256) {
        bytes1 lengthByte = bytes1(slice(data, offset, offset + 1));
        uint256 size;

        if(lengthByte < 0xfb) {
            size = 1;

            return size;
        } else if (lengthByte == 0xfb) {
            size = 2;

            return size;
        } else if (lengthByte == 0xfc) {
            size = 4;

            return size;
        } else if (lengthByte == 0xfd) {
            size = 8;

            return size;
        } else if (lengthByte == 0xfe) {
            size = 16;

            return size;
        } else {
            assert(false);

            return size;
        }
    }

    function extractMerkleRoot(bytes memory header) internal pure returns (bytes32) {
        uint256 heightSize = encodedIntegerSize(header, 32);
        bytes32 merkleRoot = bytes32(slice(header, heightSize + 32, heightSize + 64));

        return merkleRoot;
    }

    function extractBlockHeight(bytes calldata header) internal pure returns (uint256) {
        uint256 blockHeight = decodeInteger(header, 32);

        return blockHeight;
    }

    // Transaction {
    //     kind: Swap, // which kinds
    //     inputs: [
    //         CoinID {
    //             txhash: TxHash(#<456902932e51a2929e2f785588e6c7d5a3fd42646221b7fd7bef340f7dd57c25>),
    //             index: 140
    //         }
    //     ],
    //     outputs: [
    //         CoinData {
    //             covhash: Address(#<e9e4c5412b909e3a481447c1c2472c0aaf55f33033e073caa695aec06c34f8ad>),
    //             value: CoinValue(279235865177937708309490630372912481497),
    //             denom: Mel,
    //             additional_data: []
    //         },
    //         CoinData {
    //             covhash: Address(#<157e0328affa2e0fd834eb2cde74df8e22726a84b4c29fd0077d29ef96199a96>),
    //             value: CoinValue(199401219767320404375163367744579493820),
    //             denom: Mel,
    //             additional_data: []
    //         }
    //     ],
    //     fee: CoinValue(29425059478154847386909779684147829571),
    //     covenants: [[142]],
    //     data: [220, 153],
    //     sigs: [[215]] 
    // }

    // Transaction {
    //     kind: 51
    //     inputs: 01 [
    //         CoinID {
    //             txhash: 456902932e51a2929e2f785588e6c7d5a3fd42646221b7fd7bef340f7dd57c25
    //             index: 8c
    //         }
    //     ],
    //     outputs: 02 [
    //             CoinData {
    //                 covhash: e9e4c5412b909e3a481447c1c2472c0aaf55f33033e073caa695aec06c34f8ad
    //                 value: fe-d944ab34cdbce561e929b5fd15df12d2
    //                 denom: 016d
    //                 additional_data: 00 []
    //             },
    //             CoinData {
    //                 covhash: 157e0328affa2e0fd834eb2cde74df8e22726a84b4c29fd0077d29ef96199a96
    //                 value: fe-bcdf66bf896a96598dfb28a52b470396
    //                 denom: 016d
    //                 additional_data: 00 []
    //             }
    //     ],
    //     fee: fe-439ba7336e52f4d64666dde5700f2316
    //     covenants:01 [
    //         01 [
    //             8e
    //         ]
    //     ],
    //     data: 02 [
    //         dc,
    //         99
    //     ],
    //     sigs: 01 [
    //         01 [
    //             d7
    //         ]
    //     ]
    // }

    function extractValueAndRecipient(bytes calldata transaction) internal pure returns (uint256, address) {
        // skip 'kind' enum (1 byte)
        uint256 offset = 1;

        // get 'inputs' array length and add its size to 'offset'
        uint256 inputsLength = decodeInteger(transaction, offset);
        offset += encodedIntegerSize(transaction, offset);

        for(uint256 i = 0; i < inputsLength; ++i) {
            // aggregate size of each CoinData which is one hash (32 bytes) and one u8 integer (1-3 byte encoding)
            offset += encodedIntegerSize(transaction, offset) + 32;
        }

        // get the size of the 'outputs' array's length and add to offset along with 'covhash' size (32 bytes)
        offset += encodedIntegerSize(transaction, offset) + 32;

        // decode 'value', aggregate 'value' and 'denom' (2 bytes) size to 'offset'
        uint256 value = decodeInteger(transaction, offset);
        offset += encodedIntegerSize(transaction, offset) + 2;

        // get size of 'additional_data' array's length, extract recipient address from first item
        offset += encodedIntegerSize(transaction, offset);
        address recipient = address(bytes20(transaction[offset:offset + 20]));

        return (value, recipient);
    }

    function extractMelAmount() internal pure returns (uint256) {

    }

    function extractTokenType() internal pure /*returns ENUM*/ {

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

        for(uint256 i = 0; i < signers.length; ++i) {
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

        for(uint256 i = 0; i < proof.length; ++i) {
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
