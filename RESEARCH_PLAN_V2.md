# UTXO-OTS Research Plan v2: Hash-Only Single-Use Seals

Status: draft, uncommitted. Supersedes the application section of
`RESEARCH_PLAN.md`; the construction, parameter set, and security model in v1
are unchanged and are referenced rather than repeated.

## Working claim (v2)

> A UTXO-OTS bank is a single-use seal whose closing authorization and closing
> message are the same object. Closing requires the preimages; the message is
> the opened branch vector; carrier transactions are irrelevant. Under a
> client-side-validation model this yields an asset seal whose ownership and
> state transitions do not depend on any elliptic-curve assumption, using only
> standard-relay P2WSH transactions on today's Bitcoin.

The claim is scoped to client-side validation. It does not concern BTC payment
authorization; v1's boundary on that point stands and is now closed by the
FindAndDelete argument (see "Why no SegWit spending script" below).

## What changed since v1

| v1 | v2 |
| --- | --- |
| Message = arbitrary detached bytes | Message = canonical asset state transition |
| Verifier answers "did pkid sign M?" | Resolver answers "which seal owns asset X now?" |
| Copied witness listed as a payment limitation | Copied witness is the seal's defining property: it republishes the owner's transition, cannot alter it |
| One bank, one signature | Chain of banks: each transition names the receiver's bank as the next seal |
| Applications listed as candidates | One application built end to end |

## Seal mapping

Todd's single-use seal interface, instantiated on a bank:

| Seal operation | UTXO-OTS realization |
| --- | --- |
| `seal = Gen()` | Receiver derives a bank from a fresh key nonce and funds the 12 P2WSH shards. `seal_id = pkid = (network, setup_txid, first_vout, 12, parameter_set_id)` |
| `witness = Close(seal, msg)` | Owner signs `msg` with the bank (expose-before-sign), publishes aggregate or fragmented spends |
| `Verify(seal, msg, witness)` | `verify_detached_spend_set(pkid, msg, setup_outputs, scripts, spends)`: exactly one canonical spend per shard, consensus-valid openings, digits equal `SHA384(domain || pkid || len || msg)` |
| Seal is open | All 12 shard outpoints unspent on the canonical chain |
| Seal is closed | All 12 shards spent under the confirmation policy `F`; the closure message is the decoded digit vector |
| Seal is closing | Some shards spent, all observed spends decode consistently; the remainder unspent |

Deviation from RGB seals, to be stated explicitly in the write-up:

- RGB closes a seal in one transaction and commits to the message in that
  transaction (OP_RETURN or tapret). Here the message is in the witnesses and
  the closure may span several transactions and blocks.
- RGB's closure authorization is the ability to spend the seal UTXO with an
  EC key. Here it is knowledge of the preimages.
- RGB seals are one output. Here a seal is 12 outputs with a required
  contiguous layout.

## Toy asset: `seal-asset v0`

Deliberately minimal. Enough to exercise every seal property, nothing else.

### State

- `asset_id = SHA256("utxo-ots/seal-asset/v0" || genesis_pkid)`.
- Ownership is a map from `asset_id` to a set of `(seal_pkid, amount)`.
- Amounts are `u64`. Supply is fixed at genesis.

### Transitions

Two transition types, encoded as the `M` passed to `encode_message`. The
outer `utxo-ots/message/v1` domain and the signing `pkid` are already bound by
`encode_message`; the transition carries its own type tag so a genesis and a
transfer cannot be confused.

```text
Genesis  := 0x01 || "utxo-ots/seal-asset/v0" || supply:u64be
Transfer := 0x02 || asset_id:32 || n:u8 || n × ( receiver_pkid_encoded || amount:u64be )
```

Rules enforced by the resolver:

1. Genesis is signed by the seal that becomes `genesis_pkid`; it assigns
   `supply` to that same seal.
2. A transfer is valid only if signed by a seal that currently holds
   `asset_id` with some amount `a`, and `sum(amount_i) == a`.
3. Every `receiver_pkid` must name a bank whose setup outputs exist on the
   canonical chain and are unspent at the time the resolver evaluates the
   transfer, and must not already hold this asset.
4. `receiver_pkid.network` must equal the signing seal's network.
5. A seal that is closed over bytes that do not decode as a valid transition
   for an asset it holds leaves that asset in state `closed-unknown`. Nothing
   can be done with it. This is the hash-only analogue of "burned", and it is
   reachable only by the owner.

No splitting rules beyond sum equality, no metadata, no schemas, no
Lightning. All of that is RGB's job and is out of scope.

### Consignment

The off-chain package a sender hands a receiver:

```text
Consignment {
  network,
  genesis: { pkid, message_bytes },
  transitions: [ { signer_pkid, message_bytes } ],   // in causal order
  carriers:    [ raw_tx ]                             // every tx that spends any shard of any seal above
}
```

Setup transactions are fetched from the node by txid, not shipped, because
the verifier must check them against the chain anyway.

### Resolver

Input: consignment, Bitcoin Core RPC (or a static block/tx fixture),
confirmation policy `F`. Output: current owner set for the asset, or a
rejection with a reason code.

Algorithm:

1. Verify genesis seal closure with `verify_detached_spend_set` using the
   carriers; apply rule 1.
2. For each transition in order: locate the signer's 12 canonical spends in
   the carriers (`collect_spends_from_txs`), verify closure, decode, apply
   rules 2–5.
3. For every seal in the resulting owner set, confirm its shards are unspent.
   If any shard is spent, attempt to decode a closure; if no consistent
   transition is known, mark `closed-unknown`.
4. Apply `F` to every carrier used.

Reason codes should be an enum, not strings, and should be exercised by the
adversarial tests below.

## Adversarial programme

These tests are the reason for Phase A. Each is a regtest scenario plus a
unit-level equivalent where possible.

| Scenario | Expected resolver outcome |
| --- | --- |
| Honest issue then transfer A → B | Owner set `{B: supply}` |
| Attacker copies A's full witness into a tx paying the attacker; attacker's tx confirms instead of A's | Owner set `{B: supply}`; A's carrier outputs are irrelevant |
| Attacker confirms one harvested shard separately; A completes remaining 11 | Owner set `{B: supply}` once the last shard confirms; `closing` before that |
| Attacker constructs a transfer to themselves without preimages | Consensus rejects the spend (`bitcoinconsensus` failure); no carrier exists |
| A signs two conflicting transfers (to B and to C) and broadcasts both; one confirms | Owner set follows the canonical chain; A's wallet is `Poisoned`; the loser's consignment fails with `SealClosedOverDifferentMessage` |
| Transfer references a receiver bank that is already spent | `ReceiverSealNotOpen` |
| Transfer references a receiver bank on another network | `NetworkMismatch` |
| Amount sum mismatch | `SupplyMismatch` |
| A closes its seal over random bytes | Asset `closed-unknown` for A's holding |
| Consignment omits one carrier | `IncompleteShardSet` |
| Consignment reorders transitions | Rejected at the first transition whose signer does not hold the asset |
| Same transition replayed against a different `asset_id` | Rejected: `asset_id` is inside the signed bytes |

Reorganization scenarios are limited to "carrier drops below `F`
confirmations": the resolver must return to `closing` or `open`, not to a
wrong owner. Deeper reorg simulation stays in v1's open list.

## Measurements to record

For the honest issue-and-transfer path, per hop:

- setup tx vB and per-shard funding requirement at 1, 5, 20 sat/vB;
- publication vB, weight, and fee (aggregate) and the total across carriers
  (fragmented);
- consignment bytes as a function of hop count, with and without carriers;
- resolver wall time for 1, 8, 32 hops against a local regtest node;
- light-client data requirement per hop: witness bytes plus block header
  and Merkle inclusion for each carrier (witness commitment path, not txid
  path).

Cost figures feed the parameter question below; nothing else is inferred
from them here.

## Analysis items

1. **Closure time under fragmentation.** Define the closure time of a seal as
   the confirmation of its last shard. Show that no consistent partial
   closure can be completed by anyone but the owner, and that an owner who
   has published `k < 12` shards can always complete provided the remaining
   shards confirm. Note the case where remaining shards cannot confirm (fee
   exhaustion, censorship): the seal is stuck `closing` and the asset is
   frozen, not stolen.
2. **Collision resistance is load-bearing.** In v1 the signer was trusted
   with respect to itself. Here a sender who finds `M ≠ M'` with equal
   digests could hand B and C different consignments that both verify.
   Record this as the reason the digest stays at 384 bits, and estimate the
   attack cost.
3. **Burn versus theft under an EC break.** Formal statement of the table
   from the v1 discussion: EC seal allows both; EC seal plus a PQ signature
   inside the consignment allows burn only; UTXO-OTS seal allows neither
   from a non-owner.
4. **Receiver-first funding.** The receiver's bank must exist and be
   confirmed before the sender signs. Document the resulting protocol order
   and the failure mode when a sender signs to an unconfirmed or
   never-broadcast receiver setup.
5. **Parameter reduction for the seal profile.** Candidates: fewer shards via
   a different radix or digit packing, and any digest-length argument that
   survives item 2. Every candidate is re-measured against the 201-opcode,
   3,600-byte, 100-item, and 80-byte limits with Bitcoin Core as oracle.
6. **Integration surface.** A one-page mapping from `seal-asset v0` concepts
   to RGB concepts (seal definition, witness transaction, state transition,
   schema, consignment), listing exactly what RGB would have to change to
   accept a multi-output, witness-carried, fragmentable seal. No integration
   code.

## Why no SegWit spending script (closing v1's open question)

Consensus-bound spending without a soft fork needs `CHECKSIG` as a sighash
oracle plus a way to amplify one hash-to-sig puzzle (~2^46, Levy 2026) into a
strong binding. Binohash/QSB amplify by searching a nonce space that is
invisible to the pinning check yet controllable only through preimage-committed
choices; legacy `FindAndDelete` on `CHECKMULTISIG` is the only mechanism with
both properties. SegWit v0 offers `OP_CODESEPARATOR` position (about 2^7
candidates, not combinatorial) and nothing else; input sets and sequences are
attacker-controllable, and every other field is visible to pinning. Per-output
security equals that output's own script, so sharding cannot add bits.
Conclusion: QSB (legacy bare script, non-standard) is the spending
counterpart; UTXO-OTS stays on the seal side. One paragraph of this goes into
the README.

## Implementation layout (additions only)

```text
implementation/src/seal.rs          transition encoding/decoding, asset rules, reason codes
implementation/src/resolver.rs      consignment walk over verify_detached_spend_set
implementation/src/main.rs          subcommands: seal-genesis, seal-transfer, seal-resolve
implementation/tests/seal_asset.rs  adversarial programme, in-memory carriers
scripts/regtest_seal_demo.sh        issue → transfer → attacker copy → resolve
```

`keygen`, `script`, `transaction`, `verifier`, and `state` are not modified.
If a change to them turns out to be necessary it is a finding, not a
refactor, and gets written down.

## Sequence

1. Transition encoding, decoding, and rules with unit tests (no chain).
2. Resolver over in-memory carriers; positive path.
3. Adversarial programme in `seal_asset.rs`.
4. CLI subcommands and `regtest_seal_demo.sh`; measurements.
5. Analysis items 1–4 written; item 5 measured; item 6 drafted.
6. README paragraph closing the spending question.
7. Technical note: construction, seal mapping, adversarial results, tables
   from items 2 and 3, measurements, limitations.

## Stop or reframe conditions

- A copied or mutated carrier can change the decoded transition without a
  hash break. This would falsify the working claim.
- A non-owner can move a seal from `open` or `closing` to `closed` over any
  message. Same.
- Fragmented closure admits two mutually inconsistent partial closures that
  both look honest to a resolver following the canonical chain.
- The receiver-first funding order proves unworkable for any realistic
  protocol flow, and no reordering preserves the security argument.
- A prior write-up of hash-only seal ownership with witness-carried messages
  is found; reclassify as implementation and measurement.

## Out of scope for Phase A

RGB-native integration, Lightning channels, splits with change semantics
beyond sum equality, deep reorg simulation, mainnet, wallet UX, and anything
concerning BTC custody.
