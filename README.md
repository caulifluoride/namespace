# namespace

A blockchain for names, anchored in Bitcoin. Its only asset is names: there are no coins,
no fees and no block rewards.

## Design

**Consensus is Bitcoin's.** Namespace blocks are blind merge-mined using a Somsen-style
spacechain covenant: a chain of pre-signed Bitcoin transactions (key deleted), where each
covenant transaction `T_i` has

- a covenant output that only `T_{i+1}` can spend, and
- an anchor output that anyone can spend.

To anchor a namespace block, a builder spends `T_i`'s anchor output in the same Bitcoin
block with a CPFP child carrying `OP_RETURN "NSPC" <block hash>`, paying the Bitcoin fee
themselves. A relative timelock limits the covenant to one transaction per Bitcoin block,
so there's at most one anchor per Bitcoin block. Miners pick the highest-paying child.

**Fork choice.** Each header names its parent, so anchored blocks form a tree. A block is
eligible when it's anchored after its parent, its body is known, it's valid, and its parent
is eligible. The tip is the highest eligible block, with ties going to the earliest anchor.
A block whose body is withheld stalls the chain until builders anchor a longer branch on its
parent, which reorgs it out. Bitcoin reorgs unwind anchors and the namespace blocks built on
them.

**Names.**
- *Names:* 1–63 characters of `a-z0-9-`, mapping to a BIP340 x-only owner key.
- *Registering* takes two steps. First a commit of `H(name, owner, salt)`, then a reveal at
  least `min_commit_age` and at most `max_commit_age` blocks later, so a registration
  can't be front-run.
- *Expiry:* names expire `expiry_period` blocks after they're registered or last renewed.
- *Renew and transfer* are Schnorr-signed by the owner over `(name, registered_at, seq)`, so
  a signature can't be replayed, even across re-registrations.
- *Registration cap:* starts at 16 per block and doubles every `registration_doubling_interval`
  blocks up to 4096. Commits are capped at 4× that. See `Params` in `crates/core/src/params.rs`.

All rule heights are namespace heights, not Bitcoin heights, so a block's validity doesn't
depend on where its anchor lands.

## Layout

| crate         |                                                                                                             |
| ---           | ---                                                                                                         |
| `crates/core` | Consensus: encoding, hashing, txs, blocks, state transition with undo, anchor scanning, fork choice. No IO. |
| `crates/node` | `namespaced`: Bitcoin follower, redb storage, iroh P2P (block/tx propagation), local HTTP RPC.              |
| `crates/cli`  | `ns`: wallet (keygen, commit, register, renew, transfer, lookup) and block-build trigger.                   |

The node stores only block bodies and Bitcoin scan records. It rebuilds the name state on
startup by replaying the best chain.

## Running

```sh
cargo test
namespaced --network regtest \
  --bitcoin-backend esplora --bitcoin-url http://localhost:3000 \
  --covenant-start <txid>:<vout> --covenant-start-height <h> \
  [--peer <iroh endpoint id>]...

ns keygen
ns commit alice      # wait for it to be anchored
ns register alice
ns lookup alice
ns build             # builders: assemble a block, get the OP_RETURN to anchor
```

## Not done yet

- Bitcoin backends (Core RPC, Esplora, libbitcoin) are placeholders in `crates/node/src/bitcoin_source.rs`.
- Tooling to generate the pre-signed covenant chain, and to construct the anchoring CPFP child.
- Peer discovery beyond `--peer` and peers that connect to us.
- A state commitment in block headers, for light clients and name proofs.
- Persisted state snapshots, so a restart doesn't replay from genesis.
