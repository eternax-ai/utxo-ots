# Phase 0: Novelty and related-work verdict

Status: **continue, reframed**. The work is not a new cryptographic primitive
and not a new single-use-seal definition. It is a concrete Bitcoin-today
composition with a sharpened security model. If measurements or prior art later
show the composition already exists end-to-end, reclassify as an implementation
and measurement study.

## Claim under test (revised)

> Standard P2WSH outputs can pack a generalized Lamport one-time key so that
> Bitcoin consensus verifies hash-preimage openings, while an external verifier
> checks that the opened branch vector encodes a message digest. Validity is
> ledger-relative: cryptographic unforgeability, chain-relative uniqueness, and
> publication liveness are separate properties. Publication may be one aggregate
> spend or a fragmented set of spends that collectively consume the bank.

This is **not**:

- a consensus-enforced signature on the spending transaction;
- a post-quantum Bitcoin payment authorization scheme;
- a new hash-based signature family; or
- a new single-use-seal primitive.

## Prior art map

| Work | What it contributes | Relation to this project |
| --- | --- | --- |
| Lamport / Merkle / WOTS / XMSS / LMS | Hash-based OTS and stateful HBS | Cryptographic core is standard. We do not claim a new OTS. |
| NIST SP 800-208; IETF PQUIP state/backup drafts | One-time state and backup hazards | Wallet state machine must follow these lessons; ledger state does not erase them. |
| Peter Todd single-use seals (2016); RGB / LNPBP | UTXO as seal; close-over-message; client-side validation | **Established prior art for uniqueness.** Our uniqueness claim is an instance of seal closure, not a new primitive. |
| Ordinary `OP_RETURN` / witness publication of a Lamport signature | Publish signature bytes; verify fully off-chain | Closest trivial baseline. Delta must be defended explicitly (below). |
| Jeremy Rubin arithmetic Lamport; Poelstra script-state | In-Script verification of small signed values; global key-value via anti-equivocation | Different goal: Script-accessible state / covenants, not detached arbitrary-message attestation. |
| BitVM / BitVM2 | Lamport/Winternitz commitments as one-time Script state across challenge games | Uses similar hashlocks; application and security goal differ. |
| Heilman 2024 (Lamport + ECDSA length) | Consensus-bind Lamport to spending tx via `OP_SIZE` + ECDSA | Payment / covenant direction; uses `CHECKSIG`; not hash-only; not fragmented detached signing. |
| Binohash; QSB | Legacy-script tx-bound Lamport/HORS + PoW puzzles | Payment integrity without soft fork; retains ECDSA as vehicle; not our detached profile. |
| P2WOTS; WOTS-Tree | New/soft-fork PQ spend paths | Require consensus change or Taproot leaf policy; authorize value transfer. Opposite deployment axis. |

No located source describes the full composition under test: **radix-packed
P2WSH digit shards + client-validated message binding + set-of-spends /
fragmented publication + measured standardness + explicit three-property
split**, without `CHECKSIG` and without a soft fork.

Absence of a Google hit is not a theorem. The stop condition remains: if an
earlier writeup matches this composition and model, drop novelty and keep only
measurement / engineering claims.

## Delta versus “Lamport in `OP_RETURN` + single-use seal”

Single-use seals already give chain-relative uniqueness for a committed
message. Publishing a Lamport signature in an `OP_RETURN` (or witness) and
closing a seal over that commitment already yields a ledger-finalized
one-time attestation under client-side validation.

What this composition still adds, if anything:

1. **Consensus-checked openings.** Each spend must open committed hash
   branches. A seal closed over arbitrary bytes does not, by itself, prove that
   those bytes are a well-formed opening of a pre-published public key. Here the
   setup outputs *are* the public key, and Script rejects non-openings.
2. **Native key material distribution.** The 12 P2WSH outputs are the public
   key. No separate pubkey blob must be authenticated beyond the setup outpoints.
3. **Fragmented publication under witness harvesting.** Because the signature is
   a branch vector across many independently spendable shards, a copied subset
   can confirm without permanently dooming detached-message completion. An
   aggregate-only rule fails this. This is an engineering property of the
   sharded encoding, not of seals in the abstract.
4. **Measured fit under today's P2WSH policy.** Opcode, script-size, stack-item,
   and weight numbers are concrete and falsifiable (see
   `script_accounting.py`).

What it does **not** add:

- stronger message unforgeability than Lamport/WOTS under the same hash
  assumptions;
- consensus message binding;
- payment authorization;
- immunity to malicious double-exposure before confirmation.

## Gate decision

| Gate question | Answer |
| --- | --- |
| Is ledger-finalized one-time state correct? | Yes, as a single-use seal over a branch vector. |
| Meaningfully distinguishable from Lamport-in-`OP_RETURN`? | Narrowly yes: consensus-checked openings, sharded key = pubkey, fragmented set-of-spends liveness. Not a new primitive. |
| Exact construction already published? | Not found in surveyed sources. |
| Consensus/standard policy reject scripts? | No on paper; Phase 1 must confirm with Bitcoin Core. Reference shard: 2305 B script, 192 opcodes, 48 stack items, ~36 670 WU aggregate. |
| Copied witnesses change external message? | No without hash break; they replay the same branch vector. |
| Only interesting as payment signature? | No; applications are attestations / overlay authorization. |
| Continue? | **Yes**, as a construction-and-systems paper with the revised claim above. |

## What would kill the project later

- A prior writeup of the same composition and model.
- Bitcoin Core rejecting the scripts under standard policy.
- Showing that fragmented publication adds no availability property beyond
  sealing a single commitment to an off-chain signature blob.
- Quantum multi-target bounds collapsing the claimed security target without a
  parameter fix.
- Drift back into calling this a Bitcoin-native payment signature.

## Immediate Phase 0 outputs

- This memo.
- `script_accounting.py` / `script_accounting.json`: exact radix-4 serializer
  metrics and packing table.
- `SECURITY_MODEL.md`: formal split of unforgeability / uniqueness / liveness
  and the attack catalogue.
