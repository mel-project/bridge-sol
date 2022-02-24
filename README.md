# Ethereum Bridge Contract

The Ethereum bridge contract stores valid Themelio network block headers using the `relayHeader` function, which anyone can call. In order to verify that a block header is valid the contract must verifies that it has been signed by >2/3 of the Themelio block validator stake.

### Tracking Epochs

Therefore the contract also keeps track of the current themelio validator set.
The validator set is a list of `StakeDoc`s seen in the
[spec](https://docs.themelio.org/specifications/consensus-spec/#stakes).

## Contract API

### relayHeader
arguments
    - The new block header
    - List of validator signatures of the block header

First the function checks that the new block header height is within the same
epoch as the previous known block header. A block in a new epoch would require
a staker set as well.

Epochs in themelio transition at multiples of 100,000 blocks.

Then verifies the signatures match a >2/3 staker majority (weighted by stake).

Finally updates the contract's latest known block header to the new one.

### update_block_header_with_stakers
arguments
    - The new block header
    - List of validator signatures of the block header
    - A list of `StakeDoc`s representing the staker mapping at the block height
    - A merkle proof for the staker list

Verifies the staker merkle proof using the block header merkle root, and
replaces the internal contract staker list, then follows `update_block_header`
except block in a new epoch is allowed.

### mint
arguments
    - The encoded "freeze" tx on themelio as bytes
    - A merkle state proof the freeze tx

If the latest known block header does not match the height the merkle proof is
for, the proof will fail. The user needs to be sure the block height is up to
date first.

### mint_with_block_header

Combine mint and update_block_header

### burn
arguments
    - Amount of Wmel to destroy
    - Address of Wmel

This function performs an erc20 transferFrom, which must be authorized by the
owner first, to take ownership of the Wmel and then burns it.

The contract stores the (address, amount) tuple in a mapping which is used on
the themelio bridge contract to prove an address's latest burn.

TODO should the amount overwrite or accumulate?



## Building
You will need to pull down the library dependencies. Run:

```
git submodule update --init --recursive
```

We use the [foundry tools](https://github.com/gakonst/foundry) for building and testing.

Static builds of the `forge` and `cast` tools can be found [here](https://github.com/themeliolabs/artifacts).

If you would prefer to install them via `cargo`, run:

```
$ cargo install --git https://github.com/gakonst/foundry --bin forge --locked
$ cargo install --git https://github.com/gakonst/foundry --bin cast --locked
```




To build, run:
```
$ forge build
```


## Debugging

We have the option of logging via [ds-test](https://github.com/dapphub/ds-test)

To log with `ds-test`, add this line to the top of your solidity file:
```
import "ds-test/test.sol";
```

Then you can print out debugging information like this:
```
emit log("Other example print");
```


## Testing

Run:
```
$ env RUST_LOG=forge=trace forge test --vvv
```