The Ethereum bridge contract tracks the latest known block header of the
Themelio chain. This is updated with an open function that anyone can call,
`update_block_header`. In order to verify a block header is valid the contract
must check that it is signed by >2/3 of the themelio block validator stake.

### Tracking Epochs

Therefore the contract also keeps track of the current themelio validator set.
The validator set is a list of `StakeDoc`s seen in the
[spec](https://docs.themelio.org/specifications/consensus-spec/#stakes).

## Contract API

### update_block_header
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
