# Themelio Bridge Contract

This contract is a Themelio SPV client which allows users to relay Themelio staker sets,
block headers, and transactions for the purpose of creating tokenized versions of Themelio
assets, on the Ethereum network, which have already been locked up in a sister contract
previously existing on the Themelio network. Check us out at https://themelio.org !

Themelio staker sets are verified per epoch, with each epoch's staker set being verified by
the previous epoch's staker set using ed25519 signature verification (the base epoch being
introduced manually in the constructor, which can very easily be verified manually). The
staker set is an array of `StakeDoc`s seen in the [spec](https://docs.themelio.org/specifications/consensus-spec/#stakes).

Themelio block headers are validated by verifying that the included staker signatures
are authentic (using ed25519 signature verification) and that the total syms staked by all
stakers that signed the header are at least 2/3 of the total staked syms for that epoch.

Transactions are verified using the `transactions_root` Merkle root stored in their respective
block headers, in addition to a Merkle proof containing their siblings which, together, are used to
verify that the transaction is a member of the `transactions_root` Merkle tree, and thus, is
included in that block. Upon successful verification of a compliant transaction, the specified
amount of Themelio assets are minted on the Ethereum network as tokens and transferred to the
address specified in the `additional_data` field of the first output of the Themelio transaction.

To transfer tokenized Themelio assets back to the Themelio network the token holder must burn
their tokens on the Ethereum network and use the resulting transaction as a receipt which
must be submitted to the sister contract on the Themelio network to release the specified
assets.


## Themelio Bridge contract address:

* [Rinkeby testnet](https://rinkeby.etherscan.io/address/0x77653c46fbbadb73a389f99bc2a19ab5efb2ec01)



## API

### relayStakers(epoch, stakers, stakerSyms) returns (bool)

*This implementation is incomplete and will change in the near future.*

Stores Themelio staker set information for a particular epoch once the information has been
verified through ed25519 signature verification of at least 2/3 sym holders from the previous
epoch.

* `epoch`: the epoch height in `uint256`
* `stakers`: list of staker public keys `bytes32[]`
* `stakerSyms`: list amount of syms staked by each staker, in the same order as `stakers`,
`uint256[]`

Returns `true` if the staker set was successfully verified and stored, reverts otherwise.

----

### relayHeader(header, signers, signatures) returns (bool)

Stores header information for a particular block height once the header has been verified through
ed25519 signature verification of at least 2/3 sym holders from the previous epoch.

* `header`: the bincode serialized Themelio block header in `bytes`
* `signers`: list of public keys of stakers that have signed `header`, in `bytes32[]`
* `signatures`: list of signatures made by stakers, of `header`, in the same order as and twice the
size of `signers`, in a `bytes32[]`

Returns `true` if the header was successfully verified and stored, reverts otherwise.

----

### verifyTx(transaction, txIndex, blockHeight, proof) returns (bool)

Verifies the presence of a transaction on the Bitcoin blockchain, primarily that the transaction is
on Bitcoin's main chain and has at least 6 confirmations.

* `transaction`: the bincode serialized Themelio transaction, in `bytes`
* `txIndex`: the transaction's index within the block, as `uint256`
* `blockHeight`: the block height of the header `transaction` is included in, as `uint256`
* `proof` - an array of the sibling hashes comprising the Merkle proof, as `bytes32[]`

Returns `true` if the header was successfully verified and stored, reverts otherwise.

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

To run all tests, including tests which use Foreign Function Interfaces to differentially fuzz test
our Solidity functions against reference implementations in Rust, run:
```
$ forge test --vvv --ffi
```

If you only want to run the regular Solidity tests, you can use:
```
$ forge test --vvv --no-match-test FFI
```