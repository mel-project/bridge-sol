# Themelio->Ethereum Bridge

This contract acts as a bridge that allows the transfer of Themelio coins to the Ethereum
network and back, allowing users to hold and trade Themelio assets as tokens in the wider
Ethereum ecosystem and transfer them back to use on the Themelio network whenever they choose,
trustlessly. Learn more about Themelio at https://themelio.org and discover a world secured by an
unchanging trust substrate and robust incentives, not untrustworthy and centralized third-parties.

The bridge's main functionality is Themelio SPV which allows users to submit Themelio stakes, block
headers, and transactions for the purpose of creating tokenized versions of Themelio assets which
were previously locked up in a corresponding bridge covenant on Themelio (a covenant is the
Themelio equivalent of a smart contract, learn more about covenants and get started writing them at
https://melodeonlang.org/).

Themelio stakes are verified per epoch (each epoch spans 200,000 blocks), with each epoch's stakes
being verified by the previous epoch's stakers using ed25519 signature verification (the base epoch
stakes hash is introduced manually in the constructor and its authenticity can be verified very
easily by manually checking that it coincides with the stakes hash at its header's height on-chain
via Melscan, the Themelio block explorer, at https://scan.themelio.org/).

Incoming Themelio block headers are verified using the stakes hash of a trusted header that is in
the same epoch as the incoming header or is in the previous epoch, but only if it is the last
header of the previous epoch. After this, the included staker signatures are checked and must
account for at least 2/3 of all syms staked during the incoming header's epoch. 

Transactions are verified using the transactions hash Merkle root of their respective block
headers by including a Merkle proof which is used to prove that the transaction is a member of that
header's transactions Merkle tree. Upon successful verification of a compliant transaction, the
specified amount of Themelio assets will be minted on the Ethereum network as ERC-1155 tokens and
transferred to the address specified in the additional data field of the first output of the
Themelio transaction.

To transfer tokenized Themelio assets back to the Themelio network the token holder must burn
their tokens on the Ethereum network and use the resultant transaction as a receipt which must be
submitted to the bridge covenant on the Themelio network to release the specified assets.


## Themelio->Ethereum Bridge contract address:

* [Rinkeby testnet](https://rinkeby.etherscan.io/address/0x77653c46fbbadb73a389f99bc2a19ab5efb2ec01)



## API

### stakesHashes(bytes32 keccakStakesHash) returns (bytes32 blake3StakesHash)

This getter function should be used to check if a particular stakes has already been submitted
and stored via `verifyStakes()` so you don't waste gas submitting it again.

* `keccakStakesHash`: the keccak256 hash of a stakes bytes array

---

### verifyStakes(bytes stakes) returns (bool)

This function is used for hashing a stakes byte array using blake3 and storing it in contract
storage for subsequent verification of Themelio headers.

* `stakes`: a `bytes` array consisting of serialized and concatenated Themelio `StakeDoc`s, which
each represent a certain amount of `sym` coins staked on the the themelio network for a specified
amount of time by a specific public key. The `StakeDoc`s array is prepended with the amount of
total syms staked for the current and next epochs for more efficient verification of headers
in the bridge contracts.

Returns `true` if `stakes` were successfully hashed and stored, reverts otherwise.

----

### headers(uint256 blockHeight) returns (bytes32 transactionsHash, bytes32 stakesHash)

This getter function should be used to check if a header at a particular height has already been
submitted so you don't waste gas submitting it again.

* `blockHeight`: the block height of the header

---

### verifyHeader(bytes header, bytes32[] signers, bytes32[] signatures) returns (bool success)

Stores header information for a particular block height once the header has been verified through
ed25519 signature verification of stakes worth at least 2/3 of total sym staked for that epoch.

The process of header verification can be completed in multiple transactions in the case of
particularly computationally intensive verifications which exceed the block gas limit. In this
case, progress is saved in an intermediary state until the header has enough votes for
verification.

* `header`: the bincode serialized Themelio block header in `bytes`
* `signers`: array of 32-byte ed25519 public keys of stakers that have signed `header`, in
`bytes32[]`
* `signatures`: array of 64-byte ed25519 staker signatures of `header` in the same order as
`signers`, split into 32-byte `R` and 32-byte `s` (this means
`signatures.length == signers.length * 2`)

Returns `true` if the header was successfully verified and stored, reverts otherwise.

----

### verifyTx(bytes transaction, uint256 txIndex, uint256 blockHeight, bytes32[] proof) returns (bool success)

Verifies that `transaction` was included in the header at `blockHeight` by running a proof of
inclusion using `proof` and comparing the result with the transactions hash of the header. Once
the transaction has been proven to have been included in the block, the value and denomination of
the first output of the transaction will be minted and sent to the Ethereum address included in the
addition data field of the output.

* `transaction`: the bincode serialized Themelio transaction, in `bytes`
* `txIndex`: the transaction's index within the block, as `uint256`
* `blockHeight`: the block height of the header `transaction` is included in, as `uint256`
* `proof` - an array of the sibling hashes comprising the Merkle proof, as `bytes32[]`

Returns `true` if the header was successfully verified and stored, reverts otherwise.

---

### burn(address account, uint256 id, uint256 value, bytes32 themelioRecipient)

Burns `value` amount of `id` denominated tokens belonging to `account` and emits a log which
signals that the burned coins should be released to `themelioRecipient` address on the Themelio
network.

* `account`: the account owning the tokens to be burned
* `id`: the denomation id of the tokens to be burned
* `value`: the amount of tokens to be burned
* `themelioRecipient`: the address to release the burns assets to on the Themelio network

---

### burnBatch(address account, uint256[] ids, uint256[] values, bytes32 themelioRecipient)

Burns multiple denominations of tokens at a time by burning the amounts in `values` of the
corresponding denomination in `ids` belonging to `account`. Emits a log which signals that the
burned coins should be released to `themelioRecipient` address on the Themelio network.

* `account`: the account owning the tokens to be burned
* `ids`: an array of denomation ids of the tokens to be burned
* `values`: the amount of tokens to be burned
* `themelioRecipient`: the address to release the burns assets to on the Themelio network

---


## Building
You will need to pull down the library dependencies. Run:

```
git submodule update --init --recursive
```

We use the [foundry tools](https://github.com/gakonst/foundry) for building and testing.

Static builds of the `forge` and `cast` tools can be found [here]
(https://github.com/themeliolabs/artifacts).

If you would prefer to install them via `cargo`, run:

```
$ cargo install --git https://github.com/gakonst/foundry --bin forge --locked
$ cargo install --git https://github.com/gakonst/foundry --bin cast --locked
```

To build, run:
```
$ forge build
```


## Testing

To run all tests, including tests which use FFI to differentially fuzz test Solidity functions
against reference implementations in Rust, you will first have to build the Rust project in
`src/test/differentials` by running:
```
$ cd src/test/differentials && cargo build && cd ../../..
```
Then to run all tests use:
```
$ forge test --vvv --ffi
```

If you only want to run the regular Solidity tests, you can use:
```
$ forge test --vvv --no-match-test FFI
```