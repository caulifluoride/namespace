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

**State commitment.** Each header carries a `state_root`: the root of a sparse Merkle tree
over every name record and pending commitment after the block. Blocks with the wrong root
are invalid. Given a header, a light client can check a proof that a name has a given
record, or has none (`GET /proof/<name>`, `NameProof::verify`).

**The covenant chain.** Each covenant transaction is a zero-fee TRUC (v3) transaction. It
spends the previous covenant output by key path, with a one-block relative timelock, and
creates a new covenant output to the same key plus a zero-value P2A anchor output. The whole
chain is signed in advance and then the key is deleted. A covenant transaction relays only
in a package with a child that spends its anchor output. The child pays for both.

## Layout

| crate         |                                                                                                             |
| ---           | ---                                                                                                         |
| `crates/core` | Consensus: encoding, hashing, txs, blocks, state transition with undo, anchor scanning, fork choice. No IO. |
| `crates/node` | `namespaced`: Bitcoin follower, redb storage, iroh P2P (block/tx propagation), local HTTP RPC.              |
| `crates/cli`  | `ns`: wallet (keygen, commit, register, renew, transfer, lookup) and block-build trigger.                   |

The node stores block bodies, Bitcoin scan records, known-invalid blocks, known peers, and a
snapshot of the name state every 1000 blocks and on shutdown. On startup it loads the newest
snapshot that is on the best chain and matches its block's `state_root`, then replays from
there. A reorg deeper than the snapshot falls back to replaying from genesis.

Peers are found through `--peer`, through peers that connect to us, and by asking known peers
for theirs every two minutes. Peers that fail five requests in a row are dropped, except
`--peer` ones.

## Running

```sh
cargo test

# Once per chain: make the covenant.
ns covenant keygen --key-out cov.key --network regtest   # prints an address; fund it
ns covenant sign --key cov.key --funding <txid>:<vout> --amount <sats> \
  --count 10000 --out covenant.json                       # deletes cov.key

namespaced --network regtest \
  --bitcoin-backend esplora --bitcoin-url http://localhost:3000 \
  --covenant-start <txid>:<vout> --covenant-start-height <h> \
  [--peer <iroh endpoint id>]...
# or: --bitcoin-backend core --bitcoin-url http://127.0.0.1:18443 --bitcoin-auth user:pass

ns keygen
ns commit alice      # wait for it to be anchored
ns register alice
ns lookup alice
ns proof alice       # record plus Merkle proof against the state root

# Builders: build a block and anchor it.
ns anchor --chain covenant.json --network regtest --fee-rate 2 \
  --utxo <txid>:<vout> --utxo-amount <sats> --utxo-address <addr> --change <addr>
bitcoin-cli walletprocesspsbt <psbt>     # or any wallet that signs PSBTs
ns finalize <signed psbt>
bitcoin-cli submitpackage '["<covenant tx>", "<child>"]'
```

## Not done yet

- A light client that follows headers through their Bitcoin anchors, to use name proofs
  without trusting a node.
