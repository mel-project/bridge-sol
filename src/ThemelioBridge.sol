// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.13;

import 'blake3-sol/Blake3Sol.sol';
import 'ed25519-sol/Ed25519.sol';
import 'openzeppelin-contracts/contracts/token/ERC20/ERC20.sol';

/**
* @title ThemelioBridge: A relay bridge for transferring Themelio assets to Ethereum and back
*
* @author Marco Serrano (https://github.com/sadministrator)
*
* @notice This contract is a Themelio SPV client which allows users to relay Themelio staker sets,
*         block headers, and transactions for the purpose of creating tokenized versions of
*         Themelio assets, on the Ethereum network, which have already been locked up in a sister
*         contract previously existing on the Themelio network. Check us out at
*         https://themelio.org !
*
* @dev Themelio staker sets are verified per epoch (each epoch comprising 200,000 blocks), with
*      each epoch's staker set being verified by the previous epoch's staker set using ed25519
*      signature verification (the base epoch staker set being introduced manually in the
*      constructor, the authenticity of which can be verified very easily by manually checking that
*      that it coincides with the epoch's staker set on-chain).
*
*      Themelio block headers are validated by verifying that the included staker signatures
*      are authentic (using ed25519 signature verification) and that the total syms staked by all
*      stakers that signed the header are greater than 2/3 of the total staked syms for that epoch.
*
*      Transactions are verified using the 'transactions_root' Merkle root of
*      their respective block headers by including a Merkle proof which is used to verify that the
*      transaction is a member of the 'transactions_root' tree. Upon successful verification of
*      a compliant transaction, the specified amount of Themelio assets are minted on the
*      Ethereum network as tokens and transferred to the address specified in the
*      'additional_data' field of the first output of the Themelio transaction.
*
*      To transfer tokenized Themelio assets back to the Themelio network the token holder must
*      burn their tokens on the Ethereum network and use the resulting transaction as a receipt
*      which must be submitted to the sister contract on the Themelio network to release the
*      locked assets.
*
*      Questions or concerns? Come chat with us on Discord! https://discord.com/invite/VedNp7EXFc
*/
contract ThemelioBridge is ERC20 {
    using Blake3Sol for Blake3Sol.Hasher;

    /* =========== Themelio Staker Set and Header Storage =========== */

    // EpochInfo contains all relevent epoch information required for Themelio header validation
    struct EpochInfo {
        uint256 totalStakedSyms; // total syms staked by all stakers during this epoch
        mapping(bytes32 => uint256) stakers; // staker pub key => individual staked sym amount
    }

    mapping(uint256 => bytes) public headers; // necessary for validating transactions
    mapping(uint256 => EpochInfo) public epochs; // necessary for validating headers
    mapping(bytes32 => bool) public spends; // keeps track of successful token redemptions

    /* =========== Constants =========== */

    uint256 internal constant EPOCH_LENGTH = 200_000;

    bytes32 internal constant DATA_BLOCK_HASH_KEY =
        0xc811f2ef6eb6bd09fb973c747cbf349e682393ca4d8df88e5f0bcd564c10a84b;
    bytes32 internal constant NODE_HASH_KEY =
        0xd943cb6e931507cafe2357fbe5cce15af420a84c67251eddb0bf934b7bbbef91;

    /* =========== Errors =========== */

    /**
    * Slice is out of bounds. `start` must be greater than -1 and less than `dataLength`. `end`
    * must be greater than -2 and less than `dataLength` + 1.
    * @param start Starting index (inclusive).
    * @param end Ending index (exclusive).
    * @param dataLength Length of data to be sliced.
    */
    error OutOfBoundsSlice(uint256 start, uint256 end, uint256 dataLength);

    /**
    * Header at height `height` has already been relayed.
    * @param height Block height of the header being relayed.
    */
    error HeaderAlreadyRelayed(uint256 height);

    /**
    * Insufficient signatures to validate header. The total syms of stakers whose signatures were
    * able to be validated (`signerSyms`) must be greater than 2/3 of the total staked syms for
    * that epoch (`epochSyms`).
    * @param signerSyms Total syms of stakers whose signatures were verified in this transaction.
    * @param epochSyms Total amount of syms for the epoch.
    */
    error InsufficientSignatures(uint256 signerSyms, uint256 epochSyms);

    /**
    * The length of the signatures array (`signaturesLength`) must be exactly twice the length of
    * the signers array (`sigersLength`).
    * @param signersLength Length of the bytes32 array containing staker public keys.
    * @param signaturesLength Length of the bytes32 array containing the staker signatures.
    */
    error InvalidSignatures(uint256 signersLength, uint256 signaturesLength);

    /**
    * Transactions can only be verified once. The transaction with hash `txHash` has previously
    * been verified.
    * @param txHash The hash of the transaction that has already been verified.
    */
    error TxAlreadyVerified(bytes32 txHash);

    /**
    * The transaction was unable to be verified. This could be because of incorrect serialization
    * of the transaction, incorrect block height, incorrect transaction index, or improperly
    * formatted Merkle proof.
    */
    error TxNotVerified();

    /**
    * The header at block height `height` has not been relayed yet. Please relay it before
    * attempting to verify transactions at that block height.
    * @param height Block height of the header in which the transaction was included.
    */
    error MissingHeader(uint256 height);

    /* =========== Bridge Events =========== */

    event StakersRelayed(
        uint256 indexed epoch,
        bytes32[] stakers,
        uint256[] symsStaked
    );

    event HeaderRelayed(
        uint256 indexed height
    );

    event TxVerified(
        bytes32 indexed tx_hash,
        uint256 indexed height
    );

    event TokensMinted(
        address indexed recipient,
        uint256 indexed value
    );

    event TokensBurned(
        address indexed sender,
        uint256 indexed value,
        bytes32 indexed themelioRecipient
    );

    /**
    * @dev   Constructor is only responsible for submitting the token name and ticker symbol to the
    *        ERC-20 constructor.
    */
    constructor() ERC20 ('wrapped mel', 'wMEL') {}

    /* =========== ERC-20 Functions =========== */

    /**
    * @notice Returns the number of decimals in wrapped mel (wMEL).
    *
    * @dev Overrides ERC20.decimals().
    *
    * @return The number of decimals in wrapped mel (wMEL).
    */
    function decimals() public pure override returns (uint8) {
        return 9;
    }

    /**
    * @notice Burns the specified amount of wrapped mels and emits a 'TokensBurned' event which
    *         specifies the Themelio address the assets will be released to.
    *
    * @dev The process for releasing burned assets will take place in the Themelio network
    *      after the tokens have been burned in the Ethereum network.
    *
    * @param value  The number of tokens to be burned.
    *
    * @param themelioRecipient The Themelio address the burned tokens will be transferred to on the
    *        Themelio network.
    */
    function burn(uint256 value, bytes32 themelioRecipient) external {
        address sender = _msgSender();
        _burn(sender, value);

        emit TokensBurned(sender, value, themelioRecipient);
    }

    /* =========== Themelio Staker Set, Header, and Transaction Verification =========== */

    /**
    * @notice
    *
    * @dev
    *
    * @param header A serialized Themelio transaction header.
    *
    * @return 'true' if relay was successful, otherwise reverts.
    */
    function relayStakers(bytes calldata header) external returns (bool) {}

    /**
    * @notice Accepts incoming Themelio headers, validates them by verifying the signatures of
    *         stakers in the header's epoch, and stores the header for future transaction
    *         verification, upon successful validation.
    *
    * @dev The serialized header is accompanied by an array of stakers (`signers_`) that have 
    *      signed the header. Their signatures are included in another accompanying array
    *      (`signatures_`). Each signature is checked using ed25519 verification and their staked
    *      syms are added together. If at the end of the calculations the amount of staked syms
    *      from stakers that have signed is more than 2/3 of the total staked syms for that epoch
    *      then the header is successfully validated and is stored for future transaction
    *      verifications.
    *
    * @param header_ A serialized Themelio transaction header.
    *
    * @param signers_ An array of Themelio staker public keys.
    *
    * @param signatures_ An array of signatures of `header_` by each staker in `signers_`.
    *
    * @return 'true' if header was successfully validated, otherwise reverts.
    */
    function relayHeader(
        bytes calldata header_,
        bytes32[] calldata signers_,
        bytes32[] calldata signatures_
    ) external returns (bool) {
        if (signatures_.length != signers_.length * 2) {
            revert InvalidSignatures(signers_.length, signatures_.length);
        }

        uint256 blockHeight = _extractBlockHeight(header_);
        if (headers[blockHeight].length != 0) {
            revert HeaderAlreadyRelayed(blockHeight);
        }

        uint256 epochSyms = epochs[blockHeight / EPOCH_LENGTH].totalStakedSyms;
        uint256 totalSignerSyms = 0;
        uint256 signerSyms;

        for (uint256 i = 0; i < signers_.length; ++i) {
            signerSyms = epochs[blockHeight / EPOCH_LENGTH].stakers[signers_[i]];

            if (signerSyms > 0 && Ed25519.verify(
                    signers_[i],
                    signatures_[i * 2],
                    signatures_[(i * 2) + 1],
                    header_
            )) {
                totalSignerSyms += signerSyms;
            }
        }

        if (totalSignerSyms <= ((epochSyms * 2) / 3)) {
            revert InsufficientSignatures(totalSignerSyms, epochSyms);
        }

        headers[blockHeight] = header_;
        emit HeaderRelayed(blockHeight);

        return true;
    }

    /**
    * @notice Verifies the validity of a Themelio transaction by hashing it and obtaining its
    *         Merkle root using the provided Merkle proof `proof_`.
    *
    * @dev The serialized Themelio transaction is first hashed using a blake3 keyed datablock hash
    *      and then sent together with its index in the 'transactions_hash' Merkle tree,
    *      `txIndex_`, and with its Merkle proof, `proof_, to calculate its Merkle root. If its
    *      Merkle root matches the Merkle root of its corresponding header (at block
    *      `blockHeight_`), then the transaction has been validated and the 'value' field of the
    *      transaction is extracted from the first output of the transaction and the recipient is
    *      extracted from the 'additional_data' field in the first output of the transaction and
    *      the corresponding 'value' amount of tokens are minted to the Ethereum address contained
    *      in 'additional_data'.
    *
    * @param transaction_ The serialized Themelio transaction.
    *
    * @param txIndex_ The transaction's index within the 'transactions_root' Merkle tree.
    *
    * @param blockHeight_ The block height of the block header in which the transaction exists.
    *
    * @param proof_ The array of hashes which comprise the Merkle proof for the transaction.
    *
    * @return 'true' if the transaction is successfully validated, otherwise it reverts.
    */
    function verifyTx(
        bytes calldata transaction_,
        uint256 txIndex_,
        uint256 blockHeight_,
        bytes32[] calldata proof_
    ) external returns (bool) {
        bytes memory header = headers[blockHeight_];
        if (header.length == 0) {
            revert MissingHeader(blockHeight_);
        }

        bytes32 merkleRoot = _extractMerkleRoot(header);
        bytes32 txHash = _hashDatablock(transaction_);

        if(spends[txHash] == true) {
            revert TxAlreadyVerified(txHash);
        }

        if (_computeMerkleRoot(txHash, txIndex_, proof_) == merkleRoot) {
            spends[txHash] = true;

            (uint256 value, address recipient) = _extractValueAndRecipient(transaction_);
            _mint(recipient, value);

            emit TxVerified(txHash, blockHeight_);

            return true;
        } else {
            revert TxNotVerified();
        }
    }

    /* =========== Utility Functions =========== */

    /**
    * @notice Computes and returns the datablock hash of its input.
    *
    * @dev Computes and returns the blake3 keyed hash of its input argument using as its key the
    *      blake3 hash of 'smt_datablock'.
    *
    * @param datablock The bytes of a bincode-serialized Themelio transaction that is a datablock
    *        in a 'transaction_hash' Merkle tree.
    *
    * @return The blake3 keyed hash of a Merkle tree datablock input argument.
    */
    function _hashDatablock(bytes memory datablock) internal pure returns (bytes32) {
        Blake3Sol.Hasher memory hasher = Blake3Sol.new_keyed(abi.encodePacked(DATA_BLOCK_HASH_KEY));
        hasher = hasher.update_hasher(datablock);

        return bytes32(hasher.finalize());
    }

    /**
    * @notice Computes and returns the node hash of its input.
    *
    * @dev Computes and returns the blake3 keyed hash of its input argument using as its key the
    *      blake3 hash of 'smt_node'.
    *
    * @param nodes The bytes of two concatenated hashes that are nodes in a 'transaction_hash'
    *        Merkle tree.
    *
    * @return The blake3 keyed hash of two concatenated Merkle tree nodes.
    */
    function _hashNodes(bytes memory nodes) internal pure returns (bytes32) {
        Blake3Sol.Hasher memory hasher = Blake3Sol.new_keyed(abi.encodePacked(NODE_HASH_KEY));
        hasher = hasher.update_hasher(nodes);
        
        return bytes32(hasher.finalize());
    }

    /**
    * @notice Slices the `data` argument from its `start` index (inclusive) to its
    *         `end` index (exclusive), and returns the slice as a new 'bytes' array.
    *
    * @dev It can also return 'inverted slices' where `start` > `end` in order to better
    *      accomodate switching between big and little endianness in incompatible systems.
    *
    * @param data The data to be sliced, in bytes.
    *
    * @param start The start index of the slice (inclusive).
    *
    * @param end The end index of the slice (exclusive).
    *
    * @return A newly created 'bytes' variable containing the slice.
    */
    function _slice(
        bytes memory data,
        uint256 start,
        uint256 end
    ) internal pure returns (bytes memory) {
        uint256 dataLength = data.length;

        if (start <= end) {
            if (!(start >= 0 && end <= dataLength)) {
                revert OutOfBoundsSlice(start, end, dataLength);
            }

            uint256 sliceLength = end - start;
            bytes memory dataSlice = new bytes(sliceLength);

            for (uint256 i = 0; i < sliceLength; ++i) {
                dataSlice[i] = data[start + i];
            }

            return dataSlice;
        } else {
            if (!(start < dataLength && end >= 0)) {
                revert OutOfBoundsSlice({
                    start: start,
                    end: end,
                    dataLength: dataLength
                });
            }

            uint256 sliceLength = start - end;
            bytes memory dataSlice = new bytes(sliceLength);

            for (uint256 i = 0; i < sliceLength; ++i) {
                dataSlice[i] = data[start - i];
            }

            return dataSlice;
        }
    }

    /**
    * @notice Decodes and returns integers encoded at a specified offset within a 'bytes' array.
    *
    * @dev Decodes and returns integers encoded using the 'bincode' Rust crate with
    *      'with_varint_encoding' and 'reject_trailing_bytes' flags set.
    *
    * @param data_ The data, in bytes, which contains an encoded integer.
    *
    * @param offset The offset, in bytes, where our encoded integer is located at, within `data`.
    *
    * @return The decoded integer.
    */
    function _decodeInteger(bytes calldata data_, uint256 offset) internal pure returns (uint256) {
        bytes1 lengthByte = bytes1(data_[offset:offset + 1]);
        uint256 integer;

        if (lengthByte < 0xfb) {
            integer = uint8(lengthByte);
        } else if (lengthByte == 0xfb) {
            integer = uint16(bytes2(_slice(data_, offset + 2, offset)));
        } else if (lengthByte == 0xfc) {
            integer = uint32(bytes4(_slice(data_, offset + 4, offset)));
        } else if (lengthByte == 0xfd) {
            integer = uint64(bytes8(_slice(data_, offset + 8, offset)));
        } else if (lengthByte == 0xfe) {
            integer = uint128(bytes16(_slice(data_, offset + 16, offset)));
        } else {
            assert(false);
        }

        return integer;
    }

    /**
    * @notice Decodes and returns an encoded integer's size, in bytes.
    *
    * @dev Decodes and returns the size of integers encoded using the bincode Rust crate with
    *      'with_varint_encoding' and 'reject_trailing_bytes' flags set.
    *
    * @param data The data, in bytes, which contains an encoded integer.
    *
    * @param offset The offset, in bytes, where our encoded integer is located at, within `data`.
    *
    * @return The encoded integer's size, in bytes.
    */
    function _encodedIntegerSize(
        bytes memory data,
        uint256 offset
    ) internal pure returns (uint256) {
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

    /**
    * @notice Extracts and returns the 'transactions_root' Merkle root from serialized Themelio
    *         block headers.
    *
    * @dev The block headers are themelio_structs::Header structs serialized using the bincode
    *      crate with 'with_varint_encoding' and 'reject_trailing_bytes' flags set.
    *
    * @param header The serialized Themelio block header.
    *
    * @return The 32-byte 'transactions_hash' Merkle root.
    */
    function _extractMerkleRoot(bytes memory header) internal pure returns (bytes32) {
        // get size of 'block_height' using 33 as the offset to skip 'network' (1 byte) and
        // 'previous' (32 bytes)
        uint256 offset = 33;
        uint256 heightSize = _encodedIntegerSize(header, offset);

        // we can get the offset of 'transactions_root' by adding 'heightSize' + 64 to skip
        // 'history_hash' (32 bytes) and 'coins_hash' (32 bytes) 
        offset += heightSize + 64;

        bytes32 merkleRoot = bytes32(_slice(header, offset, offset + 32));

        return merkleRoot;
    }

    /**
    * @notice Extracts and decodes the height of a Themelio header.
    *
    * @dev Extracts and decodes the encoded 'height' field's value from a serialized Themelio
    *      header.
    *
    * @param header_ A serialized Themelio block header.
    *
    * @return The decoded block height of a Themelio block header.
    */
    function _extractBlockHeight(bytes calldata header_) internal pure returns (uint256) {
        // using an offset of 33 to skip 'network' (1 byte) and 'previous' (32 bytes)
        uint256 blockHeight = _decodeInteger(header_, 33);

        return blockHeight;
    }

    /**
    * @notice Extracts and decodes the value and recipient of a Themelio bridge transaction.
    *
    * @dev Extracts and decodes 'value' and 'additional_data' fields in the first CoinData struct
    *      in the 'outputs' array of a bincode serialized themelio_structs::Transaction struct.
    *
    * @param transaction_ A serialized Themelio transaction.
    *
    * @return value The 'value' field in the first output of a Themelio transaction.
    *
    * @return recipient The 'additional_data' field in the first output of a Themelio transaction.
    */
    function _extractValueAndRecipient(
        bytes calldata transaction_
    ) internal pure returns (uint256, address) {
        // skip 'kind' enum (1 byte)
        uint256 offset = 1;

        // get 'inputs' array length and add its size to 'offset'
        uint256 inputsLength = _decodeInteger(transaction_, offset);
        offset += _encodedIntegerSize(transaction_, offset);

        // aggregate size of each CoinData which is one hash (32 bytes) and one u8 integer (1 byte)
        offset += 33 * inputsLength;

        // get the size of the 'outputs' array's length and add to offset along with
        // 'cov_hash' size (32 bytes)
        offset += _encodedIntegerSize(transaction_, offset) + 32;

        // decode 'value', aggregate 'value' and 'denom' (2 bytes) size to 'offset'
        // todo: actually here we need to check the size of 'denom' because it can be 2 or 64 bytes
        uint256 value = _decodeInteger(transaction_, offset);
        offset += _encodedIntegerSize(transaction_, offset) + 2;

        // get size of 'additional_data' array's length, _extract recipient address from first item
        offset += _encodedIntegerSize(transaction_, offset);
        address recipient = address(bytes20(transaction_[offset:offset + 20]));

        return (value, recipient);
    }

    /**
    * @notice Extracts and decodes the token type of a Themelio transaction
    *
    * @dev TBD
    *
    * @param transaction_ A serialized Themelio transaction.
    * return The token type of the first output of the transaction.
    */
    function _extractTokenType(bytes calldata transaction_) internal pure {}

    /**
    * @notice Computes the a Merkle root given a hash and a Merkle proof.
    *
    * @dev Hashes a transaction's hash together with each hash in a Merkle proof in order to
    *      derive a Merkle root.
    *
    * @param txHash The hash of a serialized Themelio transaction.
    *
    * @param txIndex The index of the Themelio transaction. This is used to determine whether the
    *        'tx_hash' should be concatenated on the left or the right before hashing.
    *
    * @param proof_ An array of blake3 hashes which together form the Merkle proof for this
    *        particular Themelio transaction.
    *
    * @return The Merkle root obtained by hashing 'tx_hash' together with each hash in 'proof' in
    *         sequence.
    */
    function _computeMerkleRoot(
        bytes32 txHash,
        uint256 txIndex,
        bytes32[] calldata proof_
    ) internal pure returns (bytes32) {
        bytes32 root = txHash;
        bytes memory nodes;

        for (uint256 i = 0; i < proof_.length; ++i) {
            if (txIndex % 2 == 0) {
                nodes = abi.encodePacked(root, proof_[i]);
            } else {
                nodes = abi.encodePacked(proof_[i], root);
            }

            txIndex /= 2;
            root = _hashNodes(nodes);
        }

        return root;
    }
}
