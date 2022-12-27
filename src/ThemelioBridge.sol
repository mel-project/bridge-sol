// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.16;

import 'blake3-sol/Blake3Sol.sol';
import 'ed25519-sol/Ed25519.sol';
import 'openzeppelin-contracts-upgradeable/contracts/token/ERC1155/ERC1155Upgradeable.sol';
import 'openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol';

/**
* @title ThemelioBridge: A bridge for transferring Themelio coins to Ethereum and back
*
* @author Marco Serrano (https://github.com/sadministrator)
*
* @notice This contract uses Themelio SPV to enable users to submit Themelio stakes,
*         block headers, and transactions for the purpose of creating tokenized versions of
*         Themelio coins, on the Ethereum network, which have previously been locked up in a
*         sister covenant which resides on the Themelio network. Check us out at
*         https://themelio.org !
*
* @dev Themelio stakes are verified per epoch (each epoch spans 200,000 blocks), with
*      each epoch's stakes being verified by the previous epoch's stakers using ed25519
*      signature verification (the base epoch stakes hash is introduced manually in the constructor
*      and its authenticity can be verified very easily by manually checking that it coincides
*      with the stakes hash at its header's height on-chain via Melscan, the Themelio block
*      explorer at https://scan.themelio.org/).
*
*      Incoming Themelio block headers are verified using the stakes hash of a trusted header that
*      is in the same epoch as the incoming header or is in the previous epoch, but only if it is
*      the last header of the previous epoch. After this, the included staker signatures are
*      checked and must account for at least 2/3 of all syms staked during the incoming header's
*      epoch. 
*
*      Transactions are verified using the transactions hash Merkle root of their respective block
*      headers by including a Merkle proof which is used to prove that the transaction is a member
*      of that header's transactions Merkle tree. Upon successful verification of a compliant
*      transaction, the specified amount of Themelio coins will be minted on the Ethereum network
*      as ERC-1155 tokens and transferred to the address specified in the additional data field of
*      the first output of the Themelio transaction.
*
*      To transfer tokenized Themelio coins back to the Themelio network the token holder must
*      burn tokens with the equivalent denomination and value as a currently locked Themelio coin.
*      In the burn transaction, the burner specifies the Themelio address they want the locked
*      coin to be released to and this address can then unlock the Themelio coin at any later date.
*
*      Questions or concerns? Come chat with us on Discord! https://discord.com/invite/VedNp7EXFc
*/
contract ThemelioBridge is UUPSUpgradeable, ERC1155Upgradeable {
    using Blake3Sol for Blake3Sol.Hasher;

    // an abbreviated Themelio header with the two fields we need for header and tx validation
    struct Header {
        bytes32 transactionsHash;
        bytes32 stakesHash;
    }

    // represents an unverified Themelio header with current votes, current bytes offset, and 
    struct UnverifiedHeader { // todo: do we need to worry about different verifierHeights being used?
        uint128 votes;
        uint64 bytesVerified;
        uint64 stakeDocIndex;
    }

    // a Themelio object representing a single stash of staked syms
    struct StakeDoc {
        bytes32 publicKey;
        uint256 epochStart;
        uint256 epochPostEnd;
        uint256 symsStaked;
    }

    // a Themelio UTXO
    struct Coin {
        uint256 denom;
        uint256 value;
        bytes32 status;
    }

    /* =========== Themelio State Storage =========== */

    // maps Keccak hashes of verified stakes hash datablocks to their corresponding blockHeight
    mapping(bytes32 => uint256) public leafHeights;

    // maps Keccak hashes of unverified headers to header verification info
    mapping(bytes32 => UnverifiedHeader) public headerLimbo;

    // maps header block heights to Headers for verifying transactions and other headers
    mapping(uint256 => Header) public headers;

    // keeps track of coins and their statuses
    mapping(bytes32 => Coin) public coins;

    /* =========== Constants =========== */

    // the address of the Themelio counterpart covenant
    bytes32 internal constant THEMELIO_COVHASH = 0;

    // the number of blocks in a Themelio staking epoch
    uint256 internal constant STAKE_EPOCH = 200_000;

    // the denoms (token IDs) of coins on Themelio
    uint256 internal constant MEL = 0;
    uint256 internal constant SYM = 1;
    uint256 internal constant ERG = 2;

    // coin statuses; all other values are considered Themelio addresses
    bytes32 internal constant HYPOTHETICAL = 0;
    bytes32 internal constant MINTED = bytes32(uint256(1));

    // the hashing keys used when hashing datablocks and nodes, respectively
    bytes internal constant DATA_BLOCK_HASH_KEY = hex'c811f2ef6eb6bd09fb973c747cbf349e682393ca4d8df88e5f0bcd564c10a84b';
    bytes internal constant NODE_HASH_KEY = hex'd943cb6e931507cafe2357fbe5cce15af420a84c67251eddb0bf934b7bbbef91';

    string internal constant METADATA_URI = 'https://melscan.themelio.org/{id}.json';

    /* =========== Modifiers =========== */

    modifier onlyOwner() {
        if (_msgSender() != _getAdmin()) {
            revert NotOwner();
        }

        _;
    }

    /* =========== Errors =========== */

    /**
    * Coin cannot be burned because its status is either HYPOTHETICAL (there's no Themelio coin
    * with that transaction hash that's been bridged over to Ethereum) or it has already been
    * burned by someone else and the coin status now points to the burner's Themelio address (i.e.
    * the coin has already been redeemed).
    */
    error CannotBurn(bytes32 status);

    /**
    * Transaction sender must either be the owner or be approved by the owner of the tokens in
    * order to transfer them.
    */
    error ERC1155NotOwnerOrApproved();

    /**
    * The header was unable to be verified. This could be because of incorrect serialization
    * of the header, incorrect verifier block height, improperly formatted data, or insufficient
    * signatures.
    */
    error HeaderNotVerified();

    /**
    * The 'covhash' (Themelio address) attribute of the first output of the submitted transaction
    * must be equal to the `THEMELIO_COVHASH` constant.
    *
    * @param covhash The covenant hash of the first output of the submitted transaction.
    */
    error InvalidCovhash(bytes32 covhash);

    /**
    * Header at height `verifierHeight` cannot be used to verify header at `headerHeight`.
    * Make sure that the verifying header is in the same epoch or is the last header in the
    * previous epoch.
    *
    * @param verifierHeight Block height of header that will be used to verify the header at
    *        `headerHeight` height.
    *
    * @param headerHeight Block height of header to be verified.
    */
    error InvalidVerifier(uint256 verifierHeight, uint256 headerHeight);

    /**
    * The header at block height `height` has not been submitted yet. Please submit it with
    * verifyHeader() before attempting to verify transactions at that block height.
    *
    * @param height Block height of the header in which the transaction was included.
    */
    error MissingHeader(uint256 height);

    /**
    * Only the contract owner can call this function.
    */
    error NotOwner();

    /**
    * Transactions can only be verified once. The transaction with hash `txHash` has previously
    * been verified.
    *
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
    * The stakes datablock was unable to be verified. This could be because of incorrect serialization
    * of the datablock, incorrect block height, incorrect transaction index, or improperly
    * formatted Merkle proof.
    */
    error StakesNotVerified();

    /* =========== Bridge Events =========== */

    event StakesVerified(
        bytes32 stakesHash
    );

    event HeaderVerified(
        uint256 indexed height
    );

    event TxVerified(
        uint256 indexed height,
        bytes32 indexed txHash
    );

    event TokensBurned(
        bytes32 indexed themelioRecipient,
        bytes32[] txHashes
    );

    /**
    * @dev Initializer is responsible for initializing contract storage with a base header at 
    *      `blockHeight_` height, with `transactionsHash_` transactions hash and `stakesHash_`
    *      stakes hash, which will be used to verify subsequent headers.
    */
    function initialize(
        uint256 blockHeight_,
        bytes32 transactionsHash_,
        bytes32 stakesHash_
    ) external initializer {
        __ThemelioBridge_init(blockHeight_, transactionsHash_, stakesHash_);
    }

    function __ThemelioBridge_init(
        uint256 blockHeight_,
        bytes32 transactionsHash_,
        bytes32 stakesHash_
    ) internal onlyInitializing {
        __UUPSUpgradeable_init_unchained();
        __ERC1155_init_unchained(METADATA_URI);
        __ThemelioBridge_init_unchained(blockHeight_, transactionsHash_, stakesHash_);
    }

    function __ThemelioBridge_init_unchained(
        uint256 blockHeight_,
        bytes32 transactionsHash_,
        bytes32 stakesHash_
    ) internal onlyInitializing {
        _changeAdmin(_msgSender());

        headers[blockHeight_].transactionsHash = transactionsHash_;
        headers[blockHeight_].stakesHash = stakesHash_;

        emit HeaderVerified(blockHeight_);
    }

    /* =========== ERC-1155 Functions =========== */

    /**
     * @notice This function is used to release frozen assets on Themelio by burning them first on
     *         Ethereum. You will use the blockheight and transaction hash of your burn transaction
     *         as a receipt to release the funds on Themelio.
     *
     * @dev Destroys `value_` tokens of token type `id_` from `from_`
     *      Emits a {TransferSingle} event.
     *
     *      Requirements:
     *          - `from_` cannot be the zero address.
     *          - `from_` must have at least `amount_` tokens of token type `id_`.
     *
     * @param account_ The owner of the tokens to be burned.
     *
     * @param txHash_ The transaction hash of the coin being burned
     *
     * @param themelioRecipient_ The Themelio recipient (technically covenant) to release the
     *        funds to on the Themelio network.
     */
    function burn(
        address account_,
        bytes32 txHash_,
        bytes32 themelioRecipient_
    ) external {
        if (account_ != _msgSender() && !isApprovedForAll(account_, _msgSender())) {
            revert ERC1155NotOwnerOrApproved();
        }

        Coin storage coin = coins[txHash_]; // todo: cheaper to read in pieces?
        bytes32 coinStatus = coin.status;

        if(coinStatus != MINTED) {
            revert CannotBurn(coinStatus);
        }

        _burn(account_, coin.denom, coin.value);

        coin.status = themelioRecipient_;

        bytes32[] memory txHashes = new bytes32[](1);
        txHashes[0] = txHash_;

        emit TokensBurned(themelioRecipient_, txHashes);
    }

    /**
    * @notice This is the batch version of burn(), it can be used to burn an array of different
    *         token types using a corresponding array of values.
    *
    * @dev xref:ROOT:erc1155.adoc#batch-operations[Batched] version of {_burn}.
    *      Emits a {TransferBatch} and TokensBurned event.
    *
    *      Requirements:
    *          - `ids` and `amounts` must have the same length.
    *
    *      Emits a {TokensBurned} event.
    *
    * @param account_ The owner of the tokens to be burned.
    *
    * @param txHashes_ An array of transaction hashes identifying specific Themelio coins to be
    *                  burned.
    * @param themelioRecipient_ The Themelio recipient (technically covenant) to release the
    *        funds to on the Themelio network.
    */
    function burnBatch(
        address account_,
        bytes32[] calldata txHashes_,
        bytes32 themelioRecipient_
    ) external {
        if (account_ != _msgSender() && !isApprovedForAll(account_, _msgSender())) {
            revert ERC1155NotOwnerOrApproved();
        }
        uint256 length = txHashes_.length;

        uint256[] memory denoms;
        uint256[] memory values;
        Coin storage coin;

        for (uint256 i = 0; i > length; ++i) {
            coin = coins[txHashes_[i]];
            denoms[i] = coin.denom;
            values[i] = coin.value;
            coin.status = themelioRecipient_;
        }

        _burnBatch(account_, denoms, values);

        emit TokensBurned(themelioRecipient_, txHashes_);
    }


    /* =========== Themelio Staker Set, Header, and Transaction Verification =========== */

    /**
    * @notice Accepts a Themelio stakes tree datablock and runs a proof of inclusion on it using
    *         the stakes hash stored at the specified block height. Upon verification, the stakes
    *         hash is saved to storage so it can later be used to verify Themelio headers.
    *
    * @dev The `stakesDatablock_` is a datablock of the Themelio stakes tree which is defined in
    *      TIP-911 as being the Merkle tree composed of n datablocks where the kth datablock is the
    *      hash of the largest k stakedocs staked on the Themelio network at a certain height.
    *
    *      Emits a {StakesVerified} event.
    *
    * @param blockHeight_ The block height whose stakes hash we are verifying our datablock
    *                     against.
    *
    * @param stakesDatablock_ An array of serialized Themelio 'StakeDoc's.
    *
    * @param stakesIndex_ The index of the datablock within the stakes tree.
    *
    * @param stakesProof_ The Merkle proof for the provided datablock at the specified height.
    *
    * @return 'true' if stakes datablock was successfully validated and stored, otherwise reverts.
    */
    function verifyStakes(
        uint256 blockHeight_,
        bytes calldata stakesDatablock_,
        uint256 stakesIndex_,
        bytes32[] calldata stakesProof_
    ) external returns (bool) {
        bytes32 stakesRoot = headers[blockHeight_].stakesHash;
        bytes32 stakesLeaf = _hashDatablock(stakesDatablock_);

        if (_computeMerkleRoot(stakesLeaf, stakesIndex_, stakesProof_) == stakesRoot) {
            bytes32 keccakStakesLeaf = keccak256(stakesDatablock_);

            leafHeights[keccakStakesLeaf] = blockHeight_;

            emit StakesVerified(stakesLeaf);

            return true;
        }

        revert StakesNotVerified();
    }

    /**
    * @notice Accepts incoming Themelio headers, validates them by verifying the signatures of
    *         stakers in the header's epoch, and stores the header for future transaction
    *         verification, upon successful validation.
    *
    * @dev The serialized header is accompanied by a datablock belonging to the Themelio stakes
    *      tree at the verifier's block height. The needed signatures are included in an
    *      accompanying array. Each signature is checked using ed25519 verification and their 
    *      staked syms are added together. If at the end of the calculations the amount of staked
    *      syms from stakers that have signed is at least 2/3 of the total staked syms for that
    *      epoch then the header is successfully validated and is stored for future transaction
    *      verifications.
    *
    *      Emits a {HeaderVerified} event.
    *
    * @param header_ A serialized Themelio block header.
    *
    * @param stakesDatablock_ An array of serialized Themelio 'StakeDoc's.
    *
    * @param signatures_ An array of signatures of `header_` by each staker in `signers_`.
    *
    * @param verificationLimit_ The number of stakedocs you want to verify in a single transaction.
    *                           This allows us to store intermediate verification data in cases
    *                           where the block gas limit would otherwise be exceeded.
    *
    * @return 'true' if header was successfully validated, otherwise reverts.
    */
    function verifyHeader(
        bytes calldata header_,
        bytes calldata stakesDatablock_,
        bytes32[] calldata signatures_,
        uint256 verificationLimit_
    ) external returns (bool) {
        (
            uint256 blockHeight,
            bytes32 transactionsHash,
            bytes32 stakesHash
        ) = _decodeHeader(header_);

        bytes32 keccakStakesLeaf = keccak256(stakesDatablock_);
        uint256 stakesLeafHeight = leafHeights[keccakStakesLeaf];

        uint256 headerEpoch = blockHeight / STAKE_EPOCH;
        uint256 verifierEpoch = stakesLeafHeight / STAKE_EPOCH;

        // headers can only be used to verify headers from the same epoch, however, if they
        // are the last header of an epoch they can also verify headers one epoch ahead
        bool crossingEpoch;

        if (
            verifierEpoch != headerEpoch
        ) {
            if (stakesLeafHeight != headerEpoch * STAKE_EPOCH - 1) {
                revert InvalidVerifier(stakesLeafHeight, blockHeight);
            } else {
                crossingEpoch = true;
            }
        }

        bytes32 headerHash = keccak256(header_);
        uint256 stakeDocIndex = headerLimbo[headerHash].stakeDocIndex;
        uint256 votes;
        uint256 stakesOffset;

        if (stakeDocIndex != 0) {
            verificationLimit_ += stakeDocIndex;

            votes = headerLimbo[headerHash].votes;
            stakesOffset = headerLimbo[headerHash].bytesVerified;
        }

        // The total current epoch syms are the first value encoded in a Themelio stake tree
        // datablock; the upcoming epoch's total syms is the second value
        uint256 totalEpochSyms;
        uint256 offset;

        if (crossingEpoch) {
            (, offset) = _decodeInteger(stakesDatablock_, 0);

            if (stakesOffset == 0) {
                stakesOffset = offset;

                (totalEpochSyms, offset) = _decodeInteger(stakesDatablock_, stakesOffset);
                stakesOffset += offset;

                // this skips the unneeded encoded vector length
                (, offset) = _decodeInteger(stakesDatablock_, stakesOffset);
                stakesOffset += offset;
            } else {
                (totalEpochSyms,) = _decodeInteger(stakesDatablock_, offset);
            }
        } else {
            (totalEpochSyms, offset) = _decodeInteger(stakesDatablock_, 0);

            if(stakesOffset == 0) {
                stakesOffset = offset;

                // this skips the next epoch's total syms
                (, offset) = _decodeInteger(stakesDatablock_, stakesOffset);
                stakesOffset += offset;

                // this skips the unneeded encoded vector length
                (, offset) = _decodeInteger(stakesDatablock_, stakesOffset);
                stakesOffset += offset;
            }
        }

        StakeDoc memory stakeDoc;
        uint256 stakesLength = stakesDatablock_.length;

        for (; stakesOffset < stakesLength && stakeDocIndex < verificationLimit_; ++stakeDocIndex) {
            // this skips the transaction hash encoded in the stakes datablock
            stakesOffset += 32;

            (stakeDoc, stakesOffset) = _decodeStakeDoc(stakesDatablock_, stakesOffset);

            if (
                stakeDoc.epochStart <= headerEpoch &&
                stakeDoc.epochPostEnd > headerEpoch
            ) {
                // here we check if the 'R' part of the signature is zero as a way to skip
                // verification of signatures we do not have
                if (
                    signatures_[stakeDocIndex * 2] != 0 && Ed25519.verify(
                        stakeDoc.publicKey,
                        signatures_[stakeDocIndex * 2],
                        signatures_[stakeDocIndex * 2 + 1],
                        header_
                    )
                ) {
                    votes += stakeDoc.symsStaked;
                }
            }

            if (votes >= totalEpochSyms * 2 / 3) {
                headers[blockHeight].transactionsHash = transactionsHash;
                headers[blockHeight].stakesHash = stakesHash;

                delete headerLimbo[headerHash];

                emit HeaderVerified(blockHeight);

                return true;
            }
        }

        // if we've reached the verification limit, save current progress to storage
        if (stakesOffset < stakesLength) {
            headerLimbo[headerHash].votes = uint128(votes);
            headerLimbo[headerHash].bytesVerified = uint64(stakesOffset);
            headerLimbo[headerHash].stakeDocIndex = uint64(stakeDocIndex);

            return false;
        }

        revert HeaderNotVerified();
    }

    /**
    * @notice Verifies the validity of a Themelio transaction by hashing it and obtaining its
    *         Merkle root using the provided Merkle proof `proof_`.
    *
    * @dev The serialized Themelio transaction is first hashed using a blake3 keyed datablock hash
    *      and then sent together with its index in the 'transactions_hash' Merkle tree,
    *      `txIndex_`, and with its Merkle proof, `proof_, to calculate its Merkle root. If its
    *      Merkle root matches the Merkle root of its corresponding header (at block
    *      `blockHeight_`), then the transaction has been validated and the 'value', 'denom', and
    *      'additional_data' fields of the transaction are extracted from its first output and the
    *      corresponding 'value' amount of 'denom' tokens are minted to the Ethereum address
    *      contained in 'additional_data'.
    *
    *      Emits a {TxVerified} event.
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
        bytes32 transactionsHash = headers[blockHeight_].transactionsHash;

        if (transactionsHash == 0) {
            revert MissingHeader(blockHeight_);
        }

        bytes32 txHash = _hashDatablock(transaction_);

        if(coins[txHash].status != 0) {
            revert TxAlreadyVerified(txHash);
        }

        if (_computeMerkleRoot(txHash, txIndex_, proof_) == transactionsHash) {
            (
                bytes32 covhash,
                uint256 value,
                uint256 denom,
                address recipient
            ) = _decodeTransaction(transaction_);

            if (covhash != THEMELIO_COVHASH) {
                revert InvalidCovhash(covhash);
            }

            coins[txHash] = Coin(
                denom,
                value,
                MINTED
            );

            _mint(recipient, denom, value, '');

            emit TxVerified(blockHeight_, txHash);

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
    function _hashDatablock(bytes calldata datablock) internal pure returns (bytes32) {
        if (datablock.length == 0) return bytes32(0);

        Blake3Sol.Hasher memory hasher = Blake3Sol.new_keyed(DATA_BLOCK_HASH_KEY);
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
        if (nodes.length == 0) return bytes32(0);

        Blake3Sol.Hasher memory hasher = Blake3Sol.new_keyed(NODE_HASH_KEY);
        hasher = hasher.update_hasher(nodes);
        
        return bytes32(hasher.finalize());
    }

    /**
    * @notice Decodes and returns integers encoded at a specified offset within a 'bytes' array as
    *         well as returning the encoded integer size.
    *
    * @dev To decode an integer, we must read its length and slice the corresponding number of
    *      subsequent bytes because integers in Themelio use a variable-length encoding scheme to
    *      minimize their size.
    *
    *      After slicing, the bytes must be reversed from little-endian (the bincode default used
    *      by Themelio) to big-endian (the way they are encoded in the EVM). To do this
    *      efficiently, we employ the algorithm described here, for reversing N-bit integers in
    *      place: https://graphics.stanford.edu/~seander/bithacks.html#ReverseParallel
    *
    *      Credit to k06a finding and implementing the byte swapping algorithm for specific uints.
    *
    *      Encoding uses bincode Rust crate with 'with_varint_encoding' and 'reject_trailing_bytes'
    *      flags set.
    *
    * @param data The data, in bytes, which contains an encoded integer.
    *
    * @param offset The offset, in bytes, where our encoded integer is located at, within `data`.
    *
    * @return The decoded integer and its size in bytes.
    */
    function _decodeInteger(
        bytes calldata data,
        uint256 offset
    ) internal pure returns (uint256, uint256) {
        uint256 size;

        bytes1 lengthByte = bytes1(data[offset:offset + 1]);
        ++offset;

        if (lengthByte < 0xfb) {
            uint8 integer = uint8(lengthByte);

            size = 1;

            return (integer, size);
        } else if (lengthByte == 0xfb) {
            uint16 integer = uint16(bytes2(data[offset:offset + 2]));

            // swap bytes
            integer = (integer >> 8) | (integer << 8);

            size = 3;

            return (integer, size);
        } else if (lengthByte == 0xfc) {
            uint32 integer = uint32(bytes4(data[offset:offset + 4]));

            // swap bytes
            integer = ((integer & 0xff00ff00) >> 8) |
                ((integer & 0x00ff00ff) << 8);

            // swap 2-byte long pairs
            integer = (integer >> 16) | (integer << 16);

            size = 5;

            return (integer, size);
        } else if (lengthByte == 0xfd) {
            uint64 integer = uint64(bytes8(data[offset:offset + 8]));

            // swap bytes
            integer = ((integer & 0xff00ff00ff00ff00) >> 8) |
                ((integer & 0x00ff00ff00ff00ff) << 8);

            // swap 2-byte long pairs
            integer = ((integer & 0xffff0000ffff0000) >> 16) |
                ((integer & 0x0000ffff0000ffff) << 16);

            // swap 4-byte long pairs
            integer = (integer >> 32) | (integer << 32);

            size = 9;

            return (integer, size);
        } else if (lengthByte == 0xfe) {
            uint128 integer = uint128(bytes16(data[offset:offset + 16]));

            // swap bytes
            integer = ((integer & 0xff00ff00ff00ff00ff00ff00ff00ff00) >> 8) |
                ((integer & 0x00ff00ff00ff00ff00ff00ff00ff00ff) << 8);

            // swap 2-byte long pairs
            integer = ((integer & 0xffff0000ffff0000ffff0000ffff0000) >> 16) |
                ((integer & 0x0000ffff0000ffff0000ffff0000ffff) << 16);

            // swap 4-byte long pairs
            integer = ((integer & 0xffffffff00000000ffffffff00000000) >> 32) |
                ((integer & 0x00000000ffffffff00000000ffffffff) << 32);

            // swap 8-byte long pairs
            integer = (integer >> 64) | (integer << 64);

            size = 17;

            return (integer, size);
        } else {
            assert(false);

            // to silence compiler warning
            return (0, 0);
        }
    }


    /**
    * @notice Decodes and returns 'StakeDoc' structs.
    *
    * @dev Decodes and returns 'StakeDoc' structs encoded using the 'bincode' Rust crate with
    *      'with_varint_encoding' and 'reject_trailing_bytes' flags set.
    *
    * @param stakeDoc The serialized 'StakeDoc' struct in bytes.
    *
    * @return The decoded 'StakeDoc'.
    */
    function _decodeStakeDoc(
        bytes calldata stakeDoc,
        uint256 offset
    ) internal pure returns (StakeDoc memory, uint256) {
        StakeDoc memory decodedStakeDoc;
        uint256 integerSize;

        // first member of 'StakeDoc' struct is 32-byte 'public_key'
        decodedStakeDoc.publicKey = bytes32(stakeDoc[offset:offset + 32]);
        offset += 32;

        // 'epoch_start' is an encoded integer
        (decodedStakeDoc.epochStart, integerSize) = _decodeInteger(stakeDoc, offset);
        offset += integerSize;

        // 'epoch_post_end' is an encoded integer
        (decodedStakeDoc.epochPostEnd,  integerSize) = _decodeInteger(stakeDoc, offset);
        offset += integerSize;

        // 'syms_staked' is an encoded integer
        (decodedStakeDoc.symsStaked, integerSize) = _decodeInteger(stakeDoc, offset);
        offset += integerSize;

        return (decodedStakeDoc, offset);
    }

    /**
    * @notice Decodes a Themelio header.
    *
    * @dev Decodes the relevant attributes of a serialized Themelio header, 'stakes_hash' and
    *      'transactions_hash', which are utilized for verifying Themelio headers and transactions,
    *      respectively.
    *
    * @param header_ A serialized Themelio block header.
    *
    * @return The block height, transactions hash, and stakes hash of the header.
    */
    function _decodeHeader(bytes calldata header_)
        internal pure returns(uint256, bytes32, bytes32) {
        // using an offset of 33 to skip 'network' (1 byte) and 'previous' (32 bytes)
        uint256 offset = 33;

        (uint256 blockHeight, uint256 blockHeightSize) = _decodeInteger(header_, offset);

        // we can get the offset of 'transactions_hash' by adding `blockHeightSize` + 64 to skip
        // 'history_hash' (32 bytes) and 'coins_hash' (32 bytes)
        offset += blockHeightSize + 64;

        bytes32 transactionsHash = bytes32(header_[offset:offset + 32]);

        bytes32 stakesHash = bytes32(header_[header_.length - 32:header_.length]);

        return (blockHeight, transactionsHash, stakesHash);
    }

    /**
    * @notice Extracts and decodes the covhash, value, denom, and recipient of a Themelio
    *         transaction.
    *
    * @dev Extracts and decodes 'covhash', 'value', 'denom', and 'additional_data' fields in the
    *      first CoinData struct in the 'outputs' array of a bincode serialized
    *      themelio_structs::Transaction struct.
    *
    * @param transaction_ A serialized Themelio transaction.
    *
    * @return covhash The address of a Themelio covenant.
    *
    * @return value The 'value' field in the first output of a Themelio transaction.
    *
    * @return denom The denomination of a Themelio coin (it is converted to token id).
    *
    * @return recipient The 'additional_data' field in the first output of a Themelio transaction.
    */
    function _decodeTransaction(
        bytes calldata transaction_
    ) internal pure returns (bytes32, uint256, uint256, address) {
        // skip 'kind' enum (1 byte)
        uint256 offset = 1;

        // get 'inputs' array length and add its size to 'offset'
        (uint256 inputsLength, uint256 inputsLengthSize) = _decodeInteger(transaction_, offset);
        offset += inputsLengthSize;

        // aggregate size of each CoinData which is one hash (32 bytes) and one u8 integer (1 byte)
        offset += 33 * inputsLength;

        // get the size of the 'outputs' array's length and add to offset
        (,uint256 outputsLengthSize) = _decodeInteger(transaction_, offset);
        offset += outputsLengthSize;

        // add 'covhash' size to offset (32 bytes)
        bytes32 covhash = bytes32(transaction_[offset:offset + 32]);
        offset += 32;

        // decode 'value' and add its size to 'offset'
        (uint256 value, uint256 valueSize) = _decodeInteger(transaction_, offset);
        offset += valueSize;

        // here we need to check the size of 'denom' because it can be 0, 1, or 32 bytes
        (uint256 denomSize, uint256 denomSizeLength) = _decodeInteger(transaction_, offset);
        offset += denomSizeLength; // the size of `denomSize`; the denom metasize, if you will.

        uint256 denom;

        if (denomSize == 1) {
            uint256 coin = uint8(bytes1(transaction_[offset:offset + 1]));

            if (coin == 0x64) {
                denom = ERG;
            } else if (coin == 0x6d) {
                denom = MEL;
            } else if (coin == 0x73) {
                denom = SYM;
            } else {
                assert(false);
            }
        } else if (denomSize == 32) {
            denom = uint256(bytes32(transaction_[offset:offset + 64]));
        } else {
            assert(false);
        }

        // 'denom' size to 'offset'
        offset += denomSize;

        // get size of 'additional_data' array's length, _extract recipient address from first item
        (, uint256 additionalDataLength) = _decodeInteger(transaction_, offset);
        offset += additionalDataLength;

        address recipient = address(bytes20(transaction_[offset:offset + 20]));

        return (covhash, value, denom, recipient);
    }

    /**
    * @notice Computes the a Merkle root given a hash and a Merkle proof.
    *
    * @dev Hashes a transaction's hash together with each hash in a Merkle proof in order to
    *      derive a Merkle root.
    *
    * @param leaf_ The leaf for which we are performing the proof of inclusion.
    *
    * @param index The index of the leaf in the Merkle tree. This is used to determine whether
    *        the leaf/node should be concatenated on the left or the right before hashing.
    *
    * @param proof_ An array of blake3 hashes which together form the Merkle proof for this
    *        particular Themelio transaction.
    *
    * @return root The Merkle root obtained running the proof.
    */
    function _computeMerkleRoot(
        bytes32 leaf_,
        uint256 index,
        bytes32[] calldata proof_
    ) internal pure returns (bytes32) {
        bytes32 root = leaf_;
        bytes memory nodes;

        uint256 proofLength = proof_.length;

        for (uint256 i = 0; i < proofLength; ++i) {
            if (index % 2 == 0) {
                nodes = abi.encodePacked(root, proof_[i]);
            } else {
                nodes = abi.encodePacked(proof_[i], root);
            }

            index /= 2;
            root = _hashNodes(nodes);
        }

        return root;
    }

    /**
    * @notice This function reverts if msg.sender is not authorized to upgrade the contract.
    *
    * @dev This function is called by `upgradeTo()` and `upgradeToAndCall()` to authorize an
    *      upgrade.
    */
    function _authorizeUpgrade(address) internal override view onlyOwner {}
}
