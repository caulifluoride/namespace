# namespace

A blockchain for names, anchored in Bitcoin. Its only asset is names: there are no coins,
no fees and no block rewards.

For a walkthrough of the design, see the
[explanation resource](https://claude.ai/artifact/Bip8AmkcE6L6jxXJUwhHuH).

## Design

**Consensus is Bitcoin's.** Namespace blocks are blind merge-mined using a Somsen-style
spacechain covenant: a chain of pre-signed Bitcoin transactions (key deleted), where each
covenant transaction `T_i` has

- a covenant output that only `T_{i+1}` can spend, and
- an anchor output that anyone can spend.

To anchor a namespace block, a builder spends `T_i`'s anchor output in the same Bitcoin
block with a CPFP child carrying `OP_RETURN "NSPC" <block hash>`, paying the Bitcoin fee
themselves. A relative timelock of 3 blocks limits the covenant to one transaction every 3
Bitcoin blocks, so there's at most one anchor, and one namespace block, every 3 Bitcoin
blocks. Miners pick the highest-paying child.

**Paying builders.** Whoever gets their child confirmed on Bitcoin decides what goes in that
namespace block. The protocol has no fees of its own, so builders aren't paid by the
namespace chain. Users who want a transaction included pay a builder some other way, outside
the protocol (for example over Lightning, or with a Bitcoin payment made conditional on
inclusion). A builder can spend what it collects on its anchor's Bitcoin fee to outbid other
builders for the next slot.

**Fork choice.** Each header names its parent, so anchored blocks form a tree. A block is
eligible when it's anchored after its parent, its body is known, it's valid, and its parent
is eligible. The tip is the highest eligible block, with ties going to the earliest anchor.
A block whose body is withheld stalls the chain until builders anchor a longer branch on its
parent, which reorgs it out. Bitcoin reorgs unwind anchors and the namespace blocks built on
them.

**Names.**
- *Names:* 1–63 characters of `a-z0-9-`, mapping to a BIP340 x-only owner key.
- *Registering* takes two steps. Anyone can first *announce* a free name. Then, at least
  `announce_delay` (336) blocks later, about a week, anyone can register it to any owner
  key. The first registration to land in a block wins, so the name goes to whoever gets the
  builder of that block to include theirs. Builders compete for the slot through their
  anchors' Bitcoin fees, so that block's builder is chosen by an auction run outside the
  chain. The delay gives everyone time to see the name coming up. Announcing doesn't reserve
  the name for the announcer. A name that expires has to be announced again.
- *Expiry:* names expire `expiry_period` (52,560) blocks, about three years, after they're
  registered or last renewed.
- *Renew and transfer* are Schnorr-signed by the owner over `(name, registered_at, seq)`, so
  a signature can't be replayed, even across re-registrations.
- *Announcement tiers:* announcements are rate-limited, and shorter names open later. Names
  of `long_name_len` (10) characters or more are tier 0, and each character shorter is the
  next tier. Every tier ramps up the same way, one stage every `stage_length` (4,380) blocks,
  about three months: 1 announcement every 9 blocks, then every 3, then 1, 3, 9 and 16 per
  block. When a tier reaches 16, the next one opens. Tier 0 starts at 3 per block. A tier
  takes about 18 months to ramp up, and 1-character names open after about 13 years.
  Registrations have no cap of their own, since each one needs an announcement. See `Params`
  in `crates/core/src/params.rs`.

All rule heights are namespace heights, not Bitcoin heights, so a block's validity doesn't
depend on where its anchor lands.

**State commitment.** Each header carries a `state_root`: the root of a sparse Merkle tree
over every name record and pending announcement after the block. Blocks with the wrong root
are invalid. Given a header, a light client can check a proof that a name has a given
record, or has none (`GET /proof/<name>`, `NameProof::verify`).

**The covenant chain.** Each covenant transaction is a zero-fee TRUC (v3) transaction. It
spends the previous covenant output by key path, with a 3-block relative timelock, and
creates a new covenant output to the same key plus a zero-value P2A anchor output. The whole
chain is signed in advance and then the key is deleted. A covenant transaction relays only
in a package with a child that spends its anchor output. The child pays for both.

## Layout

| crate         |                                                                                                             |
| ---           | ---                                                                                                         |
| `crates/core` | Consensus: encoding, hashing, txs, blocks, state transition with undo, anchor scanning, fork choice. No IO. |
| `crates/node` | `namespaced`: Bitcoin follower, redb storage, iroh P2P (block/tx propagation), local HTTP RPC.              |
| `crates/cli`  | `ns`: wallet (keygen, announce, register, renew, transfer, lookup) and block-build trigger.                 |

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
ns announce alice    # anyone can register it announce_delay blocks after it's anchored
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
