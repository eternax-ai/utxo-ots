# Technical note: UTXO-OTS as a hash-only single-use seal

Phase A artifact for `RESEARCH_PLAN_V2.md`. Construction, parameter set, and
security model are those of v1; this note is the seal mapping, the toy asset,
adversarial results, measurements, and the analysis items.

Stop conditions from the plan were not triggered.

## Working claim (tested)

A UTXO-OTS bank is a single-use seal whose closing authorization and closing
message are the same object. Closing requires the preimages; the message is
the opened branch vector; carrier outputs are irrelevant. Under client-side
validation this is an asset seal whose ownership does not depend on any
elliptic-curve assumption, using standard-relay P2WSH on Bitcoin today.

This is not BTC payment authorization. That boundary is closed in
[Why no SegWit spending script](#why-no-segwit-spending-script).

## Seal mapping

Todd's interface, instantiated on a bank:

| Seal operation | UTXO-OTS realization |
| --- | --- |
| `seal = Gen()` | Receiver derives a bank and funds 12 P2WSH shards. `seal_id = pkid` |
| `witness = Close(seal, msg)` | Owner signs `msg` (expose-before-sign) and publishes aggregate or fragmented spends |
| `Verify(seal, msg, witness)` | `verify_detached_spend_set`: one canonical spend per shard, consensus-valid openings, digits = `SHA384(domain \|\| pkid \|\| len \|\| msg)` |
| Open | All 12 shard outpoints unspent on the canonical chain |
| Closed | All 12 shards spent under confirmation policy `F`; the message is the decoded digit vector |
| Closing | Some shards spent, observed digits consistent with one message; remainder unspent |

Deviations from RGB seals:

- RGB closes in one transaction and commits the message in that transaction
  (OP_RETURN or tapret). Here the message is in the witnesses and closure may
  span several transactions and blocks.
- RGB's authorization is an EC key. Here it is knowledge of the preimages.
- RGB seals are one output. Here a seal is 12 contiguous P2WSH outputs.

## Finding F-1: genesis cannot credit a transferable holding on the same bank

A bank is one-time. The v2 encoding

```text
Genesis := 0x01 || "utxo-ots/seal-asset/v0" || supply:u64be
```

assigns supply to the genesis signer, who is closed by that signature and
cannot later sign a transfer. The honest path `issue then transfer A → B`
is unsatisfiable without a second bank.

Phase A therefore accepts an optional trailing `first_holder` pkid:

```text
Genesis := 0x01 || domain || supply:u64be [ || first_holder_pkid ]
```

Omitted, the holder is the signer (parked on a closed seal). Present, supply
is assigned to that open receiver — typically the issuer's second bank, or a
mint-and-send receiver. The spec-exact encoding remains valid.

This is the RGB split between the genesis-anchor UTXO and the first owner
seal, which the original one-line rule had collapsed.

## Finding F-2: witness parsing duplicated in the resolver

`verifier.rs` is frozen. Partial closes (`Closing`) need digit extraction from
a subset of shards, which `verify_detached_spend_set` does not expose. The
resolver duplicates consensus verification and selector parsing. A later
export of `observe_spend_digits` would delete the copy.

## Toy asset

`asset_id = SHA256("utxo-ots/seal-asset/v0" || Encode(genesis_pkid))`.

Fixed `u64` supply. Transfers consume the signer's full balance. Receivers
must exist on the declared network, must not already hold the asset, and must
be open unless they are a later signer in the same consignment (so a
multi-hop history can close intermediate seals). A holder who closes over
bytes that are not a valid transition for this asset is `closed-unknown`
(hash-only burn, owner-only).

Reason codes are the `ReasonCode` enum in `implementation/src/seal.rs`.

## Adversarial results

All cases in `implementation/tests/seal_asset.rs`. In-memory chain, `F = 6`.

| Scenario | Outcome |
| --- | --- |
| Honest issue then transfer A → B | Owner `{B: supply}` |
| Attacker copies A's full witness into a tx paying the attacker; that tx confirms | Owner `{B: supply}` |
| One harvested shard confirms; A completes the remaining 11 | `Closing` with A until the last shard; then `{B: supply}` |
| Transfer without preimages | `bitcoinconsensus` rejects the spend |
| A signs transfers to B and to C; C's carrier is canonical | Owner `{C: supply}`; B's consignment `SealClosedOverDifferentMessage`; A's wallet `Poisoned` |
| Transfer to a receiver bank that is already spent | `ReceiverSealNotOpen` |
| Receiver on another network | `NetworkMismatch` |
| Amount sum ≠ signer balance | `SupplyMismatch` |
| A closes over random bytes | A's holding `closed-unknown` |
| Consignment omits one carrier | `IncompleteShardSet` |
| Transitions reordered | `SignerDoesNotHoldAsset` at the first signer who does not hold |
| Same transfer presented under a different genesis | `AssetIdMismatch` (`asset_id` is inside the signed bytes) |
| Carrier confirmations drop below `F` | `pending`, previous owner, not B |
| Carrier retracted from the view | `IncompleteShardSet`, not B |

Copied or mutated carriers did not change the decoded transition. A non-owner
could not close a seal over any message. Inconsistent partial closures are
rejected (`InconsistentPartialClosure`).

## Measurements (honest issue-and-transfer)

From `artifacts/seals/measurements.json` (debug profile, local machine).

| Item | Value |
| --- | --- |
| Setup | 567 vB, weight 2268 |
| Aggregate publication | **9168 vB**, weight 36669 |
| Fragmented publication (12 txs) | 9398 vB total |
| Aggregate witness bytes | 34619 |
| Consignment, 1 hop, with carriers | 141 418 B |
| Consignment, 1 hop, without carriers | 863 B |
| Consignment, 8 hops, with carriers | 636 065 B |
| Consignment, 32 hops, with carriers | 2 332 375 B |
| Resolver, 1 / 8 / 32 hops | 47 / 174 / 649 ms |

Per-shard funding at 1 / 5 / 20 sat/vB (dust 330 plus share of aggregate
publication fee): 1094 / 4150 / 15610 sats. Setup fee at those rates:
567 / 2835 / 11340 sats.

Light-client data per hop, witness-commitment path: ~34 619 witness bytes +
80-byte header + ~256-byte Merkle path (depth 8) + 32-byte witness Merkle
node ≈ **35 kB**, dominated by the witness. Carriers are 99% of consignment
size; shipping messages without carriers is <1 kB/hop plus whatever the
client fetches from the node.

## Analysis

### 1. Closure time under fragmentation

Define closure time as confirmation of the last shard under `F`. A consistent
partial close reveals only the digits of the intended message. Completing the
remaining shards requires the matching preimages, which only the owner has
(unforgeability of the unrevealed alternatives). An observer who copies `k`
witnesses republishes those digits and cannot choose others.

If the remaining shards cannot confirm (fee exhaustion, censorship), the seal
stays `Closing` and the asset is frozen on the previous owner, not stolen.
That is the liveness failure already named in v1, now as an asset freeze.

### 2. Collision resistance is load-bearing

In v1 the signer was trusted with respect to itself. Here a sender who finds
`M ≠ M'` with

```text
SHA384(domain || pkid || len(M) || M)
  = SHA384(domain || pkid || len(M') || M')
```

can hand B and C consignments that both verify against the same openings.

That is a prefixed SHA-384 collision. Classical birthday cost is ~2^192.
BHT quantum collision search is ~2^{384/3} = 2^128. Second-preimage (fix
the openings, find another message) is 2^384 classical / 2^192 Grover.

SHA-256 would drop the birthday bound to 2^128 classical and ~2^85 BHT, which
is the reason the digest stays at 384 bits. Eight 16-digit shards would cut
publication by about one third and still pass policy; they fail this item.

### 3. Burn versus theft under an EC break

| Attack | EC seal | EC seal + PQ sig in the consignment | UTXO-OTS seal |
| --- | --- | --- | --- |
| Steal by closing over a different transition | yes | no (recipient rejects) | no |
| Burn by closing over garbage | yes | yes | no: only the preimage holder can close |
| Copy the owner's spend into another carrier | n/a | n/a | harmless: the message is the openings |
| Jam by confirming one copied shard | n/a | n/a | no: set-of-spends completion |

An EC seal lets a Shor-capable adversary both steal and burn. A PQ signature
inside the consignment stops theft and still allows burn. A UTXO-OTS seal
allows neither from a non-owner. The owner can still burn (`closed-unknown`)
by closing over junk; that is deliberate.

### 4. Receiver-first funding

Protocol order:

1. Receiver derives a bank, funds 12 shards, waits for `F` on the setup.
2. Receiver sends `pkid` (setup txid, vout, network, parameter set).
3. Sender checks the setup on the canonical chain and that all 12 shards are
   unspent.
4. Sender signs the transfer (expose-before-sign) and publishes.
5. Sender hands the consignment to the receiver.

If the sender signs to an unconfirmed or never-broadcast receiver setup, the
transfer names a `pkid` the resolver cannot load (`SetupNotFound`) or that
is not open. The sender's seal is already closed over those bytes. The
holding becomes `closed-unknown`: the owner burned the asset. There is no
safe reordering that lets the sender sign first. Batch pre-funding of
receiver banks is the wallet implication.

### 5. Parameter reduction for the seal profile

Re-measured radix-4 IF-tree scripts with Bitcoin Core's opcode counting
(`count_ops`) against 201 / 3600 / 100 / 80. Full table:
`artifacts/seals/param_study.json`.

- 16 digits / shard: 2305 B, 192 ops, 48 items — inside limits, 9 opcode
  headroom. This is the reference shard.
- 17 digits / shard: 204 ops — **fails the 201-opcode limit**. More packing
  on radix-4 is not available.
- SHA-256, same shards: 8 outputs, same per-shard script, ~33% fewer vbytes.
  Rejected by item 2.
- Higher radix (8 or 16) needs a wider IF-tree and more ops per digit, so
  fewer digits per shard and no free lunch without touching `script.rs`.

No candidate both reduces on-chain cost and survives the collision bar
without a new script family. The seal profile stays `sha384-w4-d16-s12-v1`.

### 6. Integration surface (RGB)

| `seal-asset v0` | RGB |
| --- | --- |
| `pkid` (12-output bank) | single-use seal (one outpoint) |
| Setup tx | seal UTXO creation |
| Aggregate or fragmented spends | witness transaction (one tx) |
| Transition bytes in the witness branch vector | state transition committed by OP_RETURN / tapret / opret |
| `asset_id` + genesis rules | schema / contract genesis |
| Consignment (messages + carriers) | RGB consignment |
| Resolver + `F` | client-side validation + confirmation policy |
| `closed-unknown` | no direct analogue (EC burn is a third party) |

What RGB would have to change to accept this seal:

1. **Seal definition.** A seal is a vector of 12 outpoints with a required
   contiguous layout, not one outpoint.
2. **Witness transaction.** Closure is a set of spends, possibly across
   blocks. The commitment is the opened digits, not an output of a single
   carrier. Tapret/opret on the carrier is not the message.
3. **Single-use check.** Uniqueness is "each of the 12 outpoints is spent
   exactly once on the canonical chain under `F`", with fragmented
   completion.
4. **Schema.** State transitions remain RGB's; only the seal and commitment
   scheme are replaced. No schema work is in this repo.
5. **Consignment.** Must carry or fetch every shard spend, not one witness
   tx. Setup txs are fetched by txid.

No integration code. The toy asset is RGB-shaped, not RGB-native.

## Why no SegWit spending script

Consensus-bound spending without a soft fork needs `CHECKSIG` as a sighash
oracle plus a way to amplify one hash-to-sig puzzle (~2^46, Levy 2026) into a
strong binding. Binohash/QSB amplify by searching a nonce space that is
invisible to the pinning check yet controllable only through
preimage-committed choices; legacy `FindAndDelete` on `CHECKMULTISIG` is the
only mechanism with both properties. SegWit v0 offers `OP_CODESEPARATOR`
position (about 2^7 candidates, not combinatorial) and nothing else; input
sets and sequences are attacker-controllable, and every other field is
visible to pinning. Per-output security equals that output's own script, so
sharding cannot add bits. QSB (legacy bare script, non-standard) is the
spending counterpart; UTXO-OTS stays on the seal side.

## Limitations

- Receiver-first funding and ~9.2 kvB publication. Treasury / issuance
  profile, not retail payments.
- No historical UTXO snapshot: "receiver was open at time T" is approximated
  by current spends plus consignment causality.
- Deep reorgs remain on v1's open list; this note only drops carriers below
  `F`.
- Frozen core (`keygen`, `script`, `transaction`, `verifier`, `state`) was
  not modified except as noted in F-2 (duplication, not a patch).
- `Cargo.toml` had a duplicate `[[bin]]` that current Cargo rejects; the
  extra stanza was removed so the crate builds.

## Layout

```text
implementation/src/seal.rs
implementation/src/resolver.rs
implementation/src/main.rs          seal-genesis, seal-transfer, seal-resolve, seal-copy-attack
implementation/tests/seal_asset.rs
implementation/tests/param_study.rs
scripts/regtest_seal_demo.sh
artifacts/seals/measurements.json
artifacts/seals/param_study.json
```
