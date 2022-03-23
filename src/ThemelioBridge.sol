// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.10;

import 'blake3-sol/Blake3Sol.sol';
import 'ed25519-sol/Ed25519.sol';
import 'openzeppelin-contracts/contracts/token/ERC20/ERC20.sol';

contract ThemelioBridge is ERC20 {
    struct EpochInfo {
        uint256 stakedSyms;
        mapping(bytes32 => uint256) stakers;
    }

    mapping(uint256 => bytes) public headers;
    mapping(uint256 => EpochInfo) public epochs;

    event HeaderRelayed(uint256 indexed height);
    event TxVerified(bytes32 indexed tx_hash, uint256 indexed height);

    bytes32 private immutable DATA_BLOCK_HASH_KEY;
    bytes32 private immutable NODE_HASH_KEY;

    string private constant ERR_OUT_OF_BOUNDS = 'Out of bounds slice.';
    string private constant ERR_ALREADY_RELAYED = 'Header already relayed.';
    string private constant ERR_INSUFFICIENT_SIGNATURES = 'Insufficient signatures.';
    string private constant ERR_INVALID_SIGNATURES = 'Improperly formatted signatures.';
    string private constant ERR_UNRELAYED_HEADER = 'Header must be relayed first.';

    Blake3Sol blake3 = new Blake3Sol();

    constructor() ERC20 ('wrapped mel', 'wMEL') {
        Hasher memory node_hasher = blake3.new_hasher();
        node_hasher = blake3.update_hasher(node_hasher, 'smt_node');
        NODE_HASH_KEY = bytes32(blake3.finalize(node_hasher));

        Hasher memory leaf_hasher = blake3.new_hasher();
        leaf_hasher = blake3.update_hasher(leaf_hasher, 'smt_datablock');
        DATA_BLOCK_HASH_KEY = bytes32(blake3.finalize(leaf_hasher));
    }

    function decimals() public pure override returns (uint8) {
        return 9;
    }

    function _hashLeaf(bytes memory leaf) internal returns (bytes32) {
        Hasher memory hasher = blake3.new_keyed(abi.encodePacked(DATA_BLOCK_HASH_KEY));
        hasher = blake3.update_hasher(hasher, leaf);

        return bytes32(blake3.finalize(hasher));
    }

    function _hashNodes(bytes memory nodes) internal returns (bytes32) {
        Hasher memory hasher = blake3.new_keyed(abi.encodePacked(NODE_HASH_KEY));
        hasher = blake3.update_hasher(hasher, nodes);

        return bytes32(blake3.finalize(hasher));
    }

    function _slice(bytes memory data, uint256 start, uint256 end) internal pure returns (bytes memory) {
        uint256 dataLength = data.length;

        if (start <= end) {
            require(
                start < dataLength &&
                start >= 0 &&
                end <= dataLength,
                ERR_OUT_OF_BOUNDS
            );

            uint256 sliceLength = end - start;
            bytes memory dataSlice = new bytes(sliceLength);

            for (uint256 i = 0; i < sliceLength; ++i) {
                dataSlice[i] = data[start + i];
            }

            return dataSlice;
        } else {
            require(
                start < dataLength &&
                start >= 0 &&
                int256(end) >= -1,
                ERR_OUT_OF_BOUNDS
            );

            uint256 sliceLength = start - end;
            bytes memory dataSlice = new bytes(sliceLength);

            for (uint256 i = 0; i < sliceLength; ++i) {
                dataSlice[i] = data[start - i];
            }

            return dataSlice;
        }
    }

    function _decodeInteger(bytes calldata data, uint256 offset) internal pure returns (uint256) {
        bytes1 lengthByte = bytes1(data[offset:offset + 1]);
        uint256 integer;

        if (lengthByte < 0xfb) {
            integer = uint8(lengthByte);
        } else if (lengthByte == 0xfb) {
            integer = uint16(bytes2(_slice(data, offset + 2, offset)));
        } else if (lengthByte == 0xfc) {
            integer = uint32(bytes4(_slice(data, offset + 4, offset)));
        } else if (lengthByte == 0xfd) {
            integer = uint64(bytes8(_slice(data, offset + 8, offset)));
        } else if (lengthByte == 0xfe) {
            integer = uint128(bytes16(_slice(data, offset + 16, offset)));
        } else {
            assert(false);
        }

        return integer;
    }

    function _encodedIntegerSize(bytes memory data, uint256 offset) internal pure returns (uint256) {
        bytes1 lengthByte = bytes1(_slice(data, offset, offset + 1));
        uint256 size;

        if (lengthByte < 0xfb) {
            size = 1;
        } else if (lengthByte == 0xfb) {
            size = 3;
        } else if (lengthByte == 0xfc) {
            size = 5;
        } else if (lengthByte == 0xfd) {
            size = 9;
        } else if (lengthByte == 0xfe) {
            size = 17;
        } else {
            assert(false);
        }

        return size;
    }

    function _extractMerkleRoot(bytes memory header) internal pure returns (bytes32) {
        // get size of 'block_height' using 33 as the offset to skip 'network' (1 byte) and 'previous' (32 bytes)
        uint256 offset = 33;
        uint256 heightSize = _encodedIntegerSize(header, offset);

        // we can get the offset of 'merkle_root' by adding 'heightSize' + 64 to skip 'history_hash' (32 bytes) and 'coins_hash' (32 bytes) 
        offset += heightSize + 64;

        bytes32 merkleRoot = bytes32(_slice(header, offset, offset + 32));

        return merkleRoot;
    }

    function _extractBlockHeight(bytes calldata header) internal pure returns (uint256) {
        // using an offset of 33 to skip 'network' (1 byte) and 'previous' (32 bytes)
        uint256 blockHeight = _decodeInteger(header, 33);

        return blockHeight;
    }

    function _extractValueAndRecipient(bytes calldata transaction) internal pure returns (uint256, address) {
        // skip 'kind' enum (1 byte)
        uint256 offset = 1;

        // get 'inputs' array length and add its size to 'offset'
        uint256 inputsLength = _decodeInteger(transaction, offset);
        offset += _encodedIntegerSize(transaction, offset);

        for (uint256 i = 0; i < inputsLength; ++i) {
            // aggregate size of each CoinData which is one _hash (32 bytes) and one u8 integer (1-3 byte encoding)
            offset += _encodedIntegerSize(transaction, offset) + 32;
        }

        // get the size of the 'outputs' array's length and add to offset along with 'cov_hash' size (32 bytes)
        offset += _encodedIntegerSize(transaction, offset) + 32;

        // decode 'value', aggregate 'value' and 'denom' (2 bytes) size to 'offset'
        uint256 value = _decodeInteger(transaction, offset);
        offset += _encodedIntegerSize(transaction, offset) + 2;

        // get size of 'additional_data' array's length, _extract recipient address from first item
        offset += _encodedIntegerSize(transaction, offset);
        address recipient = address(bytes20(transaction[offset:offset + 20]));

        return (value, recipient);
    }

    function _extractTokenType(bytes calldata transaction_) internal pure {}

    function relayStakers(bytes calldata stakerInfo_) external returns (bool) {}

    function relayHeader(
        bytes calldata header_,
        bytes32[] calldata signers_,
        bytes calldata signatures_
    ) external returns (bool) {
        require(signatures_.length % 64 == 0, ERR_INVALID_SIGNATURES);

        uint256 blockHeight = _extractBlockHeight(header_);
        require(headers[blockHeight].length == 0, ERR_ALREADY_RELAYED);

        uint256 epochSyms = epochs[blockHeight / 100000].stakedSyms;
        uint256 totalSignerSyms = 0;
        uint256 signerSyms;

        for (uint256 i = 0; i < signers_.length; ++i) {
            signerSyms = epochs[blockHeight / 100000].stakers[signers_[i]];

            if (signerSyms > 0 && Ed25519.verify(
                    signers_[i],
                    bytes32(signatures_[i * 64:(i * 64) + 32]),
                    bytes32(signatures_[(i * 64) + 32:(i * 64) + 64]),
                    header_
            )) {
                totalSignerSyms += signerSyms;
            }
        }

        require(totalSignerSyms > ((epochSyms * 2) / 3), ERR_INSUFFICIENT_SIGNATURES);

        headers[blockHeight] = header_;
        emit HeaderRelayed(blockHeight);

        return true;
    }

    function _computeMerkleRoot(
        bytes32 tx_hash,
        uint256 txIndex,
        bytes32[] calldata proof
    ) internal returns (bytes32) {
        bytes32 root = tx_hash;
        bytes memory nodes;

        for (uint256 i = 0; i < proof.length; ++i) {
            if (txIndex % 2 == 0) {
                nodes = abi.encodePacked(root, proof[i]);
            } else {
                nodes = abi.encodePacked(proof[i], root);
            }
            txIndex /= 2;
            root = _hashNodes(nodes);
        }

        return root;
    }

    function verifyTx(
        bytes calldata transaction_,
        uint256 txIndex_,
        uint256 blockHeight_,
        bytes32[] calldata proof_
    ) external returns (bool) {
        bytes memory header = headers[blockHeight_];
        require(header.length > 0, ERR_UNRELAYED_HEADER);

        bytes32 merkleRoot = _extractMerkleRoot(header);
        bytes32 txHash = _hashLeaf(transaction_);

        if (_computeMerkleRoot(txHash, txIndex_, proof_) == merkleRoot) {
            uint256 value;
            address recipient;

            (value, recipient) = _extractValueAndRecipient(transaction_);
            _mint(recipient, value);

            emit TxVerified(txHash, blockHeight_);

            return true;
        } else {
            return false;
        }
    }
}
