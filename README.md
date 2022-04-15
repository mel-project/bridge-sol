# Themelio Bridge Contract

This contract allows users to relay Themelio staker sets, block headers, and transactions
for the purpose of creating tokenized versions of Themelio assets, on the Ethereum
network, which have been previously locked up in a sister contract existing on the Themelio
network.

Themelio staker sets are verified per epoch, with each epoch's staker set being verified by
the previous epoch's staker set using ed25519 signature verification (the base epoch being
introduced manually in the constructor, which can very easily be verified manually).
The staker set is an array of `StakeDoc`s seen in the [spec](https://docs.themelio.org/specifications/consensus-spec/#stakes).
Themelio block headers are then validated by verifying their included staker signatures
using ed25519 signature verification. Transactions are verified using the 'transactions_root'
Merkle root of their respective block headers by including a Merkle proof which is used to verify
the transaction is a member of the 'transactions_root' tree. Upon successful verification of
a compliant transaction, the specified amount of Themelio assets are minted on the
Ethereum network as tokens and transferred to the address specified in the
'additional_data' field of the first output of the Themelio transaction. To transfer
tokenized Themelio assets back to the Themelio network the token holder must burn their
tokens on the Ethereum network and use the resulting transaction as a receipt which must
be submitted to the sister contract on the Themelio network to release the specified assets.

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