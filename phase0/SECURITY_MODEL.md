# Phase 0: Security model and attack catalogue

## Three properties (do not collapse them)

UTXO-OTS validity is a conjunction of three separable properties. Prior
art already names pieces of this split (Lamport unforgeability; Todd
single-use seals; RGB/client-side validation). The contribution is to keep
them formally apart for this Bitcoin encoding.

### 1. Cryptographic unforgeability (hash-only)

**Experiment (sketch).** Challenger generates a bank `(pkid, setup_tx)`.
Adversary may request one signature on a chosen message `M`. After observing
the published branch openings (and any losing mempool transcripts the model
allows), the adversary wins by producing an accepting transcript for
`M' ≠ M` under the same `pkid` without a new honest sign operation.

**Winning requires** (informally):

- a SHA-256 preimage for at least one unrevealed digit alternative; or
- a SHA-384 collision / second preimage that preserves all opened digits; or
- breaking commitment / encoding domain separation.

**Does not depend on** Bitcoin consensus, fees, or confirmations. A fully
off-chain transcript of the same openings is equally forgeable or not.

**Preliminary concrete target.** After one signature, 192 digits × 3 closed
alternatives = 576 unrevealed SHA-256 targets. Idealized Grover on one
32-byte preimage ≈ 128 bits; naive multi-target discount
`0.5·log2(576) ≈ 4.6` bits → ≈ 123.4 bits. This is a planning bound, not a
theorem, until a chosen-message multi-target reduction is written.

### 2. Chain-relative uniqueness (single-use seal)

**Statement.** Relative to a fixed Bitcoin network and a confirmation /
finality policy `F`, there is at most one `F`-accepted canonical spend set
for the setup outpoints. Therefore at most one branch vector is
ledger-final for that bank under `F`.

**This is Peter Todd's single-use seal instantiated on the shard outpoints.**
It does not cryptographically erase conflicting preimages that appeared in
losing transactions or private channels. It only prevents two different
spend sets from being simultaneously canonical.

**Reorgs.** If `F` is “k confirmations on the current best chain,” uniqueness
is only as stable as that chain prefix. A deeper reorg can replace the
canonical spend set. Unforgeability of hash openings is unchanged; the
ledger-relative signature may change.

### 3. Publication liveness (fragmentation tolerance)

**Statement.** If some strict subset of shard witnesses is copied into
conflicting transactions that confirm, and those spends reveal the same
branch choices the signer intended, then the signer can still complete a
valid detached-message signature by confirming spends of the remaining
shards that reveal the same digest vector—provided the remaining shards
are still unspent and can be confirmed under network conditions.

**Failure mode under aggregate-only rules.** If verification requires one
transaction that consumes every shard, confirming any harvested single-shard
conflict permanently prevents completion. That is a denial of publication,
not a forgery.

**Non-goals for liveness.** The property does not guarantee confirmation
against miner censorship, fee exhaustion, or a malicious signer who reveals
conflicting alternatives. It only removes a self-inflicted structural DoS
from the verification rule.

## Detached-message validity predicate

Accept `(M, pkid, spendSet)` iff all hold:

1. `pkid` names a confirmed setup bank on the declared network with the
   declared parameter set.
2. `spendSet` contains exactly one confirmed canonical spend witness for
   each setup outpoint (possibly across several carrier transactions).
3. Each witness succeeds as P2WSH against its setup scriptPubKey
   (consensus script checks).
4. Parsed selectors form a 192-digit base-4 vector `v`.
5. `v` equals the base-4 expansion of
   `SHA384(domain || Encode(pkid) || len(M) || M)`.
6. The application's finality policy `F` accepts every spend's chain
   ancestry.

Carrier txids, outputs, fees, and aggregation are intentionally excluded
from (4)–(5).

## Payment non-equivalence (negative claim)

Bitcoin Script does not read the message or the spending transaction into
the branch checks. Therefore a copied witness that opens the same
commitments can satisfy consensus for a transaction with arbitrary outputs.
External verification of `M` or of a txid profile may reject that carrier;
consensus need not. Any text that calls this a “Bitcoin payment signature”
without a consensus binding mechanism is false.

The txid-signing profile is retained only as a negative experiment:
aggregate self-signing is structurally killed by single-shard harvesting.

## Attack catalogue

| Attack | Affects | Outcome under detached set-of-spends profile |
| --- | --- | --- |
| Forge `M'` after one honest signature | Unforgeability | Fail unless hash break / collision. |
| Copy full witness, mutate outputs | Payment binding | Consensus may accept carrier; detached `M` unchanged; txid profile fails external check. |
| Copy one shard, confirm separately | Liveness (aggregate-only) | Aggregate-only: fatal DoS. Set-of-spends: partial publication; complete remaining shards. |
| Copy shards with same selectors | Uniqueness / message | Same message; no second digest. |
| Conflicting selectors in two mempool txs | Unforgeability + wallet | At most one canonical spend set confirms; leaked losing preimages can poison the bank; wallet must mark `poisoned`/`exposed`. |
| Signer double-signs off-chain | Unforgeability | Outside forger still needs closed preimages; verifier who saw only one transcript may accept a signature the signer later equivocated on off-chain. |
| Reorg deeper than `F` | Uniqueness | Canonical signature can change; re-verify under new chain. |
| Cross-network replay | Domain separation | Reject via `pkid.network` and domain tags. |
| Nonminimal selectors / malformed stacks | Implementation | Must reject canonically; consensus may have different minimalty rules—pin to tested encodings. |
| Fee drain / censor remaining shards | Liveness | Possible; not a forgery. Setup value and operational fee policy matter. |
| Stale backup resign | Wallet state | Must not return bank to `funded` after `exposed`. |
| Pretend OP_RETURN blob is this scheme | Openings | Without P2WSH openings against setup commitments, predicate (3) fails. |

## Malicious signer versus outside forger

- **Outside forger:** limited by unforgeability. Cannot open closed
  branches without hash break.
- **Malicious signer:** can reveal multiple alternatives before
  confirmation, leak losing witnesses, or withhold publication. Seals
  stop dual *canonical* finality; they do not stop dual *exposure*.

Papers and code must keep this distinction visible in every security claim.

## Comparison table (property ownership)

| Property | Provided by | Not provided by |
| --- | --- | --- |
| Unforgeability | Hash commitments + one-time branch reveal | UTXO set, PoW, fees |
| Uniqueness | Canonical UTXO spend (seal) | Hash function alone |
| Message binding | External digest check | Bitcoin Script (today) |
| Payment authorization | — | This construction |
| Publication under subset harvest | Set-of-spends rule + remaining shards | Aggregate-only rule |

## Stop conditions tied to this model

Reframe or stop if:

1. Uniqueness is marketed as unforgeability.
2. External message checks are described as consensus payment rules.
3. Aggregate-only verification is proposed as the robust profile.
4. Fragmented publication is shown to be useless relative to sealing a
   single off-chain Lamport blob (i.e., the sharded P2WSH openings add no
   defended property).
