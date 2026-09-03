# Spend-to-Sign: Research and Implementation Plan

## Working claim

**Phase 0 verdict (2026-09-03): continue, reframed.** Single-use seals are
prior art (Todd, RGB). The project does not claim a new seal primitive or a new
hash-based signature family. The claim under test is a concrete composition:

> Standard P2WSH shards can encode a generalized Lamport one-time key so that
> Bitcoin consensus verifies hash-preimage openings, an external verifier checks
> that the opened branch vector encodes a message digest, and publication may be
> one aggregate spend or a fragmented set of spends. Cryptographic
> unforgeability, chain-relative uniqueness, and publication liveness are
> separate properties.

Artifacts: `phase0/NOVELTY.md`, `phase0/SECURITY_MODEL.md`,
`phase0/script_accounting.py`.

The construction uses no `OP_CHECKSIG`, no transaction introspection, no new
opcode, and no elliptic-curve security assumption in key generation, Script
execution, or external verification. It does **not** provide a post-quantum
Bitcoin payment condition: consensus checks openings; an overlay checks the
message. That boundary is load-bearing.

The older one-sentence demo slogan ("ledger-finalized OTS with only SHA-256
hashlocks") remains directionally fine only when paired with the three-property
split and the external-verification boundary.

## Core observation

A conventional Lamport-style one-time key requires persistent state: after one
signature, the same key must never sign another message. Bitcoin already
maintains a globally ordered, replicated set of objects that can each be
consumed at most once.

The proposal maps logical one-time signing cells onto UTXOs:

- the locking scripts contain the hash commitments;
- witness branches select the signed digest digits;
- revealed preimages form the signature material;
- UTXO consumption records which one-time key bank was finalized; and
- Bitcoin proof of work provides ordering, timestamping, and probabilistic
  finality.

The signature is therefore ledger-relative. It is valid only with respect to a
specified Bitcoin network and canonical-chain view.

## Important boundary: signature versus payment authorization

The witness scripts check only that each disclosed value opens one committed
branch. They cannot check that the selected branches equal the digest of the
current transaction or of an arbitrary message because existing Bitcoin Script
cannot read transaction data as stack values.

Consequently:

- copying a valid witness into a conflicting transaction does not reveal a
  different signature;
- copying and separately confirming one shard contributes the same signed
  digits rather than invalidating the detached signature;
- changing the transaction's outputs does not change the branch choices;
- an external verifier can reject the modified transaction as a signature on
  its own txid; but
- Bitcoin consensus may still accept that modified transaction.

The construction can provide a hash-only attestation or authorization artifact.
It cannot, by itself, protect valuable inputs or force payment outputs to match
the signed message. Any application that acts on the signature is an overlay
verifier unless a future Bitcoin opcode makes the message-to-branch relation a
consensus predicate.

This limitation is central rather than incidental. The project stops or
reframes if its only interesting claim depends on describing external
verification as native Bitcoin payment authorization.

## Candidate construction

### 1. Parameter set

The initial conservative parameter set is:

- message digest: SHA-384;
- digest length: 384 bits;
- digit radix: \(w=4\);
- logical digits: \(384 / \log_2 4 = 192\);
- secret-preimage length: 32 bytes;
- alternatives per digit: four;
- logical digits per P2WSH shard: 16;
- physical P2WSH shards: 12;
- hash commitment: SHA-256; and
- confirmation policy: application-defined, with six confirmations as the
  reference evaluation point rather than a cryptographic finality claim.

SHA-384 is computed by the external signer and verifier. Bitcoin Script uses
only `OP_SHA256`. The 384-bit message digest avoids making generic quantum
collision search on a 256-bit message digest the dominant bound. A single
SHA-256 preimage or P2WSH second preimage has approximately 128 bits of security
under idealized Grover search; multi-target search across the 576 unrevealed
digit alternatives lowers the preliminary system bound to approximately 123.4
bits and requires a concrete analysis.

These parameters are provisional until the implementation measures exact
script bytes, opcode counts, witness elements, transaction weight, and relay
policy behavior.

### 2. Key generation

For every logical digit \(i \in \{0,\ldots,191\}\) and choice
\(j \in \{0,1,2,3\}\), derive an independent secret

\[
    s_{i,j} =
    \operatorname{HMAC\text{-}SHA256}
    (K,\text{``spend-to-sign/secret/v1''}\parallel
    \mathit{keyNonce}\parallel i\parallel j)
\]

and commitment

\[
    c_{i,j} = \operatorname{SHA256}(s_{i,j}).
\]

The master seed \(K\) and random `keyNonce` remain private. Each physical shard
contains commitments for 16 consecutive logical digits. The setup transaction
creates 12 native P2WSH outputs, preferably at consecutive output indices and
with equal values.

The compact public-key identifier is:

\[
    \mathit{pkid} =
    (\mathit{network},\mathit{setupTxid},\mathit{firstVout},
    \mathit{shardCount},\mathit{parameterSet}).
\]

The setup outputs themselves are the authoritative public key. A verifier
retrieves and checks their P2WSH script commitments from the canonical chain.

### 3. P2WSH digit verification

For each base-4 digit, the witness supplies:

- one 32-byte preimage; and
- two minimally encoded Boolean selector values.

A balanced nested `OP_IF` tree selects one of four hardcoded commitments. The
script then hashes the supplied preimage and compares it with the selected
commitment. In schematic form:

```text
# Initial stack for this digit: <preimage> <lowBit> <highBit>
OP_IF
    OP_IF <c3> OP_ELSE <c2> OP_ENDIF
OP_ELSE
    OP_IF <c1> OP_ELSE <c0> OP_ENDIF
OP_ENDIF
OP_SWAP
OP_SHA256
OP_EQUALVERIFY
```

After all 16 digits pass, the shard script pushes true. Exact witness order,
derived from `phase0/script_exec_test.py`: push digits **15…0**, each as
`<preimage> <lowBit> <highBit>` (highBit on top). See
`phase0/SCRIPT_TEMPLATE.md`.

One digit uses 132 serialized commitment bytes and 12 non-push opcodes in the
schematic encoding. Sixteen digits therefore provisionally produce:

- a 2,305-byte witness script, below the 3,600-byte standard P2WSH policy
  limit;
- 192 counted opcodes, below the 201-opcode consensus limit;
- 48 data items plus the witness script, below the 100-item standard P2WSH
  policy limit; and
- 32-byte preimage items and one-byte selectors, below the 80-byte standard
  witness-item policy limit.

All unexecuted branches count toward the opcode limit. Exact serialization and
opcode counts are mandatory test outputs.

### 4. Message encoding

The detached-message profile computes

\[
    d =
    \operatorname{SHA384}(
    \text{``spend-to-sign/message/v1''}\parallel
    \operatorname{Encode}(\mathit{pkid})\parallel
    \operatorname{EncodeLength}(M)\parallel M).
\]

Canonical binary length-prefixing is required. JSON is permitted only for
diagnostics.

The digest is parsed into 192 base-4 digits. For each digit \(i\), the signer
reveals \(s_{i,d_i}\) and selector bits encoding \(d_i\).

A second experimental profile signs a SegWit transaction's txid. Because P2WSH
witnesses are excluded from the txid, the transaction skeleton and txid can be
computed before inserting the branch witnesses. This avoids a serialization
cycle, but the branch-to-txid relation remains externally verified rather than
consensus-enforced. It also requires atomic aggregate confirmation and is
therefore retained as an intentionally attacked negative baseline, not a
candidate robust profile.

### 5. Publication transactions

The preferred fast path uses one aggregate publication transaction that:

1. consumes all 12 setup shards;
2. supplies the 192 selected preimages and branch selectors across their
   witnesses;
3. uses canonical final sequences unless a test profile explicitly studies
   replacement policy;
4. creates one minimal zero-value `OP_RETURN` output; and
5. pays its fee from the equal-valued shard inputs.

Detached-message validity does not require atomic consumption. If an observer
copies one shard witness into a separately confirmed conflict, the signer
rebuilds publication transactions for the remaining unspent shards. The final
signature is the ordered set of confirmed witnesses that collectively consumes
the complete bank and encodes one digest. Carrier transaction identity and
outputs are deliberately excluded from detached-message validity.

This set-of-spends rule is necessary for public-mempool robustness. An
aggregate-only rule would let an observer harvest one revealed shard, confirm it
separately, and permanently prevent the required all-input transaction from
confirming.

The reference profile burns the complete shard value as fees rather than
pretending that their value is safely payable to a recipient. Setup values must
be high enough to satisfy both the 330-satoshi P2WSH dust threshold at creation
and the intended publication feerate at consumption.

Equal shard values are not required for unforgeability. They provide predictable
fee capacity, avoid assigning semantic meaning to shard value, simplify wallet
accounting, and make every physical state cell operationally interchangeable.

### 6. Verification

Given \((M,\mathit{pkid},\mathit{spendSet})\), a full verifier:

1. checks that the setup transaction is confirmed on the selected Bitcoin
   network;
2. resolves the 12 expected setup outpoints and verifies their P2WSH programs;
3. locates the canonical confirmed spend of every shard, whether the shards
   were consumed by one aggregate transaction or several carrier transactions;
4. applies the application's confirmation or chain-finality policy;
5. executes or independently validates each P2WSH witness;
6. parses selectors using one canonical encoding;
7. recomputes the SHA-384 message digest and its base-4 digits;
8. checks every observed branch against the corresponding digest digit; and
9. rejects unknown parameter sets, incomplete shard sets, duplicate shards,
   noncanonical encodings, and cross-network replays.

A light-client verifier additionally needs authenticated access to the setup
outputs, every relevant spending transaction including witness data, and the
corresponding Bitcoin witness commitments. A txid Merkle proof alone does not
authenticate SegWit witness bytes.

## Measured aggregate-fast-path footprint (serializer)

Exact radix-4 nested-IF serialization (`phase0/script_accounting.py`), still
pending Bitcoin Core `testmempoolaccept` confirmation:

- 12 P2WSH setup outputs;
- 16 logical digits per witness script (opcode-maximal packing: 17 digits
  exceeds the 201-opcode consensus limit);
- **2,305-byte** witness script per shard (1,295 bytes under the 3,600 policy
  cap);
- **192** counted opcodes (9 of headroom before 201; binding constraint);
- **48** witness stack items excluding the script (52 of headroom before 100);
- 32-byte max data item (under the 80-byte policy cap);
- approximately 34,620 witness bytes and **36,670 weight / 9,168 vB** for a
  one-`OP_RETURN` aggregate publication; and
- no signature operations.

Among even SHA-384/radix-4 packings, 16 digits × 12 shards minimizes estimated
aggregate weight; 12×16 and 8×24 are the next even alternatives. Fragmented
publication overhead is not yet measured. Bitcoin Core remains the oracle for
standardness.

## Security model

### Adversary

The adversary may:

- observe the setup transaction and every script commitment;
- choose messages adaptively;
- observe unconfirmed and confirmed signature witnesses;
- copy witnesses into conflicting transactions;
- mutate non-witness transaction fields and outputs;
- submit higher-fee conflicts directly to miners;
- reorganize the chain within an explicitly modeled depth;
- run quantum algorithms, including Grover-style preimage search; and
- control ordinary network transport and mempool propagation.

The adversary does not initially know the master seed or unrevealed preimages.

### Intended properties

- **One-time unforgeability:** after one valid signature, producing a valid
  signature for a distinct message requires either an unrevealed SHA-256
  preimage or a digest collision/second preimage.
- **Hash-only verification core:** no elliptic-curve or number-theoretic
  assumption appears in key generation, Script execution, or external
  verification.
- **Canonical-chain uniqueness:** every shard has at most one canonical spend,
  so one branch choice per logical digit becomes final relative to a stable
  chain view.
- **Copy robustness for the signed message:** copying the revealed witnesses
  reproduces the same branch vector; it does not create a signature on a
  different digest.
- **Fragmentation tolerance:** confirming a copied strict subset with the same
  branch choices cannot prevent detached-message completion from the remaining
  unspent shards, assuming those shards can eventually be confirmed.
- **Domain separation:** signatures cannot be moved across keys, parameter
  sets, networks, or protocol versions through ambiguous encoding.

### Required limitations

- **No native output binding.** Consensus does not verify that branch choices
  match the message or spending transaction.
- **No prevention of off-chain double signing.** A signer can reveal different
  branch secrets in conflicting transactions before confirmation. Even if only
  one confirms, leaked losing witnesses may compromise the one-time key.
- **Mempool state still matters.** UTXO finality improves state observability but
  does not replace advance-before-sign wallet discipline.
- **Carrier mutation and fragmentation.** An observer can copy witnesses into
  conflicting transactions, alter carrier outputs, or confirm a strict subset
  of shards. The detached-message profile treats matching subset spends as
  partial publication and completes from the remaining shards. Any profile
  requiring one aggregate carrier transaction instead suffers a fatal
  witness-harvesting denial of service.
- **No robust self-transaction profile.** If validity requires one aggregate
  transaction to sign its own txid, separately confirming one copied shard
  permanently prevents that transaction from confirming. The txid profile is a
  negative experiment unless an additional binding mechanism eliminates this
  attack.
- **Probabilistic finality.** A reorganization can replace the canonical spend
  and therefore the ledger-relative signature state.
- **Setup identity is external.** The construction proves control of the
  preimages committed by `pkid`; attribution of `pkid` to a person or
  institution requires a separate identity mechanism.
- **One signature per bank.** A new setup bank is required for every signature.

The paper must distinguish a malicious signer who deliberately releases
multiple alternatives from an outside forger. Bitcoin prevents two conflicting
spends from coexisting in one canonical UTXO state; it does not erase secrets
published in losing transactions or private transcripts.

## Security analysis

### Correctness

For an honestly generated key and message, every disclosed preimage hashes to
the commitment selected by the corresponding base-4 digit, every shard script
returns true, and the external verifier reconstructs the same digest.

### Forgery after one signature

After observing one signature, an adversary knows one preimage per logical
digit. A distinct digest changes at least one digit unless the adversary finds a
collision. For every changed digit, the adversary must recover an unrevealed
SHA-256 preimage or exploit a commitment ambiguity.

The analysis must give concrete classical and quantum bounds and account for:

- multi-target preimage search across all unrevealed alternatives;
- chosen-message collision attacks against SHA-384;
- second-preimage attacks after an honest signature;
- P2WSH witness-script second preimages;
- deterministic secret derivation from one seed; and
- any reduction loss from 192 digits and four alternatives per digit.

The preliminary target is approximately 123 bits of post-quantum security after
the simple multi-target loss across 576 unrevealed alternatives. That number
must not be claimed as a theorem until a concrete chosen-message and
multi-target analysis supports it.

### Ledger state

Finalized UTXO consumption acts as a set of public single-use seals. It does not
provide cryptographic erasure. The analysis must cover:

- two conflicting signatures released before either confirms;
- a copied-witness conflict with identical branch choices;
- a strict-subset witness-harvesting conflict and completion from the remaining
  shards;
- conflicts with different branch choices;
- stale backups and parallel signing processes;
- reorganization before and after the verifier's confirmation threshold; and
- a verifier that sees only one branch transcript while another exists
  off-chain.

### Payment non-equivalence

Prove or demonstrate explicitly that a copied witness can validate a transaction
with altered outputs at the Bitcoin Script layer. This negative test prevents
the implementation or paper from accidentally treating the construction as a
post-quantum Bitcoin payment signature.

## Research questions

1. Is the construction meaningfully different from an ordinary Lamport
   signature whose public key happens to be stored in P2WSH outputs?
2. Does canonical-chain consumption provide a useful formal property beyond
   ordinary signer-maintained one-time state?
3. What is the right security definition for a signature whose validity
   requires a blockchain state transition?
4. Can a copied-witness replacement ever verify as a different message under
   the canonical encoding?
5. What exact guarantees survive if the original signing transaction loses a
   mempool race but its copied witnesses confirm elsewhere?
6. Can the number of shards, witness bytes, or setup outputs be reduced without
   weakening standard relay or post-quantum security?
7. Is radix four close to the optimal tradeoff under the 201-opcode,
   3,600-byte-script, 100-item, and 80-byte-item policy limits?
8. Can a safe batch setup create many independent signature banks from one HD
   seed without introducing state confusion?
9. Can an SPV-compatible proof authenticate the relevant witness data without
   requiring a full node?
10. Which applications genuinely benefit from a ledger-finalized signature
    that does not authorize Bitcoin outputs?

## Candidate applications

Applications must consume the artifact as an externally verified attestation,
not as a native Bitcoin spending rule. Candidate demonstrations include:

- timestamped post-quantum signing of a paper, software release, or public
  statement;
- a Bitcoin-anchored emergency authorization signal interpreted by a custody
  system;
- one-time governance or recovery votes;
- public randomness commitments with one-time branch selection;
- a hash-only authorization input to a bridge or federation; and
- an experimental policy overlay that rejects actions not accompanied by a
  finalized Spend-to-Sign artifact.

The first public demonstration should sign the paper source hash or a release
manifest. It should not place meaningful funds under the experimental scheme.

## Implementation layout

```text
utxo-ots/
├── RESEARCH_PLAN.md
├── phase0/
│   ├── NOVELTY.md
│   ├── SECURITY_MODEL.md
│   ├── SCRIPT_TEMPLATE.md
│   ├── script_accounting.py
│   ├── script_accounting.json
│   └── script_exec_test.py
├── main.tex
├── references.bib
├── implementation/
│   ├── Cargo.toml
│   ├── README.md
│   ├── src/
│   │   ├── lib.rs
│   │   ├── parameters.rs
│   │   ├── keygen.rs
│   │   ├── script.rs
│   │   ├── transaction.rs
│   │   ├── signer.rs
│   │   ├── verifier.rs
│   │   ├── state.rs
│   │   ├── rpc.rs
│   │   └── main.rs
│   ├── tests/
│   │   ├── vectors.rs
│   │   ├── script_limits.rs
│   │   ├── regtest.rs
│   │   ├── conflicting_spends.rs
│   │   ├── copied_witness.rs
│   │   └── reorg.rs
│   └── test-vectors/
└── artifacts/
    ├── benchmarks/
    ├── regtest/
    └── diagrams/
```

Use the maintained Rust `bitcoin` crate for serialization and script
construction, with Bitcoin Core as the consensus and policy oracle. Do not
implement transaction serialization or txid calculation from scratch.

No master seed, `keyNonce`, unrevealed preimage, wallet backup, or live
spend-capable descriptor may be committed under the draft or artifact
directories.

## Wallet state machine

Each signature bank has the states:

```text
generated -> funding -> funded -> signing -> exposed -> publishing
                                      \             \-> partially-confirmed
                                       \                         \-> confirmed
                                        \-> poisoned
```

- `generated`: secrets exist locally but no setup transaction is final.
- `funding`: setup transaction broadcast but not sufficiently confirmed.
- `funded`: all shards are confirmed and unspent.
- `signing`: one process holds an exclusive durable lease on the bank.
- `exposed`: any branch preimage may have left the device; the bank must never
  sign another message, even if no transaction confirms.
- `publishing`: aggregate or fragmented carrier transactions are in flight.
- `partially-confirmed`: at least one shard has a canonical spend with the
  expected branch choices; publication continues with the remaining shards.
- `confirmed`: every shard has a canonical spend encoding the same expected
  digest and satisfies the confirmation policy.
- `poisoned`: conflicting exposure, rollback, inconsistent chain state, or
  uncertain secret release occurred.

The durable transition to `exposed` happens before returning signature material
to a caller. Restoring a stale backup must never move an exposed bank back to
`funded`.

## Testing strategy

### Cryptographic tests

- HMAC-SHA256 derivation known-answer vectors.
- SHA-256 preimage commitments and SHA-384 message digest vectors.
- Base-4 encoding covers exactly 192 digits with no endian ambiguity.
- Every one of four selector paths accepts its matching preimage.
- Every selector path rejects the other three preimages.
- Mutating one message bit changes the expected branch vector.
- Cross-key, cross-network, and cross-parameter verification fails.

### Script and policy tests

- Exact witness-script size is below 3,600 bytes.
- Exact counted opcodes are at most 201, including unexecuted branches.
- Initial witness stack has at most 100 items.
- Every non-script witness item is at most 80 bytes.
- Total stack depth remains below consensus limits.
- All pushes and `OP_IF` selectors use standard minimal encodings.
- Setup outputs pass dust and standard-script checks.
- Signing transaction remains below 400,000 weight units.
- `testmempoolaccept` accepts setup and signing transactions under an
  unmodified reference Bitcoin Core node.

### State and adversarial tests

- Two processes cannot lease one bank concurrently.
- Crash before exposure returns safely to `funded`.
- Crash after possible exposure leaves the bank `exposed` or `poisoned`.
- Stale backup restoration cannot reuse a bank.
- Copy the complete witness into a transaction with mutated outputs: Bitcoin
  Script may accept it, while external message or txid verification must fail.
- Copy one shard witness into a separately confirmed transaction: aggregate-only
  verification must fail, while set-of-spends verification must treat it as
  partial publication and accept after the remaining shards confirm.
- Copy the witness without changing selector choices: it must not verify for a
  different message except through a digest collision.
- Reveal different alternatives in two conflicting transactions and confirm
  that the wallet permanently poisons the bank.
- Simulate one- through six-block reorganizations and verify chain-relative
  status transitions.
- Omit, duplicate, reorder, or substitute physical shards.
- Use nonminimal selector encodings and malformed witness stacks.

### Differential verification

For every generated test vector:

1. run the independent Rust verifier;
2. validate scripts with the `bitcoinconsensus` library when available;
3. submit through Bitcoin Core `testmempoolaccept`;
4. mine on regtest and verify canonical UTXO consumption; and
5. compare parsed branch choices against a simple reference implementation.

All test runs write structured, secret-redacted logs with parameter-set id,
public-key id, transaction ids, weights, script metrics, state transitions, and
failure codes.

## Evaluation

Measure:

- setup transaction bytes, weight, dust requirement, and fee;
- aggregate and fragmented publication transaction sizes, weights, and fees;
- exact script size, opcode count, witness-item count, and stack depth;
- key generation, signing, full-node verification, and external verification
  time;
- private seed-only storage versus fully precomputed secret storage;
- Bitcoin Core mempool acceptance across pinned supported releases;
- confirmation and reorganization behavior;
- copied-witness conflict behavior;
- batch generation cost for 1, 16, 256, and 1,024 one-time banks; and
- comparison with Lamport, WOTS+, XMSS/LMS, Heilman's transaction-signing
  construction, QSB/Binohash, and proposed P2WOTS-style output types.

Benchmarks must record hardware, operating system, Bitcoin Core version, Rust
toolchain, dependency revisions, node policy configuration, and feerate.

## Work plan and gates

### Phase 0: Novelty and fatal-flaw review — **done (continue, reframed)**

Deliverables:

- related-work memo: `phase0/NOVELTY.md` (Todd/RGB seals, Lamport-in-`OP_RETURN`,
  Rubin/Poelstra/BitVM script state, Heilman, Binohash/QSB, P2WOTS/WOTS-Tree);
- precise security and non-security claims: `phase0/SECURITY_MODEL.md`
  (unforgeability / uniqueness / liveness split + attack catalogue);
- Script template and resource accounting: `phase0/script_accounting.py`
  (exact 2305 B / 192 ops / 48 items; packing table); and
- attack catalogue: included in `SECURITY_MODEL.md`.

Gate result: uniqueness is a single-use seal (not novel). The composition remains
narrowly distinguishable from Lamport-in-`OP_RETURN` via consensus-checked
openings, setup-UTXO-as-pubkey, and fragmented set-of-spends liveness. Continue
as a construction-and-systems paper; do not claim a new primitive. Reclassify as
measurement-only if matching prior composition is found.

### Phase 1: Script prototype — **done for ship slice**

Deliverables complete for open-source demo:

- keygen, radix-4 scripts, setup, aggregate + **fragmented** publication;
- detached verifier for single tx and set-of-spends;
- CLI + `scripts/regtest_demo.sh`;
- Core `testmempoolaccept` exercised on regtest.

Still optional later: txid-profile negative oracle, setup change-address CLI flag.

### Phase 2: State and adversarial harness — **partial (shipped core)**

Shipped:

- durable `BankStore` state machine with expose-before-sign;
- fragmented harvest-completion test;
- copied-witness mutated-output consensus test;
- second-sign blocked after expose.

Still open: process lock, crash-injection matrix, reorg simulator, stale-backup
fuzzing.

### Phase 3: Security analysis and optimization

Deliverables:

- formal ledger-relative one-time unforgeability definition;
- concrete classical and quantum bounds;
- proof sketch or reduction;
- radix and shard-packing search;
- exact standardness and weight measurements; and
- full comparison against ordinary off-chain Lamport signatures.

Gate: independent review confirms that every payment-authorization limitation
and malicious-signer state failure is explicit.

### Phase 4: Reproducible demonstration

Deliverables:

- one-command regtest demonstration;
- deterministic public test vectors;
- signed source-release or paper-manifest example;
- verifier that operates from a full-node RPC endpoint;
- benchmark artifact package; and
- short technical demonstration video.

Gate: no mainnet transaction until the verifier, state machine, and copied-
witness tests are complete and independently reviewed.

### Phase 5: Paper

Deliverables:

- concise construction-and-systems paper;
- reproducibility appendix;
- security and limitations sections;
- final related-work analysis; and
- optional minimal-value mainnet signature after explicit execution approval.

Gate: use “Bitcoin-native payment signature” only if consensus itself verifies
the signed transaction relation. The present construction should instead be
described as a “Bitcoin-ledger-finalized one-time signature.”

## Paper outline

1. **Introduction.** Bitcoin's UTXO set as one-time cryptographic state.
2. **Background.** Lamport signatures, stateful hash signatures, P2WSH, and
   Bitcoin double-spend semantics.
3. **Model.** Ledger-relative validity, adversary, confirmation policy, and
   external message verification.
4. **Construction.** Setup shards, radix-four branches, aggregate and fragmented
   publication, and verification.
5. **Security.** Correctness, one-time unforgeability, quantum bounds, conflicts,
   witness copying, and reorganizations.
6. **Implementation.** Bitcoin Core integration, wallet state, serialization,
   and standardness.
7. **Evaluation.** Weight, fees, latency, storage, and radix tradeoffs.
8. **Applications.** Timestamped attestations and externally enforced
   authorization.
9. **Related work.** Hash-based signatures, Bitcoin transaction-signing
   constructions, stateful UTXO schemes, and blockchain-secured primitives.
10. **Limitations.** No consensus message binding, no native payment protection,
    one-time state, and probabilistic finality.

The target is a short construction-and-implementation paper. It should not
present a new hash-based signature primitive; the proposed contribution is the
ledger-enforced representation and its measured Bitcoin realization.

## Novelty and stop conditions

**Initial search status:** seals and client-side validation are prior art; no
surveyed source matches the full composition (P2WSH digit shards + external
message check + fragmented set-of-spends + measured standardness +
three-property model) without `CHECKSIG` or a soft fork. Details in
`phase0/NOVELTY.md`.

Keep searching while implementing. Stop or reframe if:

- the exact construction and security model already exist;
- consensus or standard policy rejects the proposed P2WSH scripts;
- copied witnesses can change the externally verified message without a hash
  break;
- the quantum multi-target bound falls materially below the stated target;
- sharded P2WSH openings add no defended property over sealing an off-chain
  Lamport blob;
- safe use requires hiding a state-management assumption;
- the only meaningful application is native payment authorization; or
- the paper cannot explain its external-verification boundary in one sentence.

If the construction is known but lacks a reproducible Bitcoin Core
implementation, reframe as an implementation, measurement, and state-safety
study and label it accordingly.

## Initial references

- Leslie Lamport, *Constructing Digital Signatures from a One-Way Function*.
- Ralph Merkle, *A Certified Digital Signature*.
- Johannes Buchmann, Erik Dahmen, and Andreas Hülsing, work on XMSS and
  hash-based signature state.
- NIST SP 800-208, *Recommendation for Stateful Hash-Based Signature Schemes*.
- IETF PQUIP, *Hash-Based Signatures: State and Backup Management*.
- Andrew Poelstra, *Script State From Lamport Signatures*.
- BitVM and BitVM2 work using Lamport commitments as one-time Script state.
- Peter Todd, work on *single-use seals* and client-side validation.
- RGB protocol work composing Bitcoin outpoints with client-side-validated
  single-use state.
- Ethan Heilman, *Signing a Bitcoin Transaction with Lamport Signatures (no
  changes needed)*.
- Robin Linus, *Binohash: Signing Bitcoin Transactions via Proof of Work*.
- Avihu Mordechai Levy, *Quantum Safe Bitcoin (QSB)*.
- Javier P. Mateos, *WOTS-Tree: Merkle-Optimized Winternitz Signatures for
  Post-Quantum Bitcoin*.
- Current P2WOTS Bitcoin development discussions and reference implementation.
- Bitcoin Core policy and interpreter sources for the pinned implementation
  release.
