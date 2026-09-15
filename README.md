# UTXO-OTS

**Bitcoin-ledger-finalized one-time signatures using only SHA-256 hashlocks and standard P2WSH — no new opcodes, no `CHECKSIG`, no soft fork.**

You create 12 native P2WSH outputs (the public key). To sign a message, you spend them and reveal one preimage per digest digit. Bitcoin consensus checks the openings; an external verifier checks that the branch vector encodes the message. Publication can be one aggregate transaction or a **fragmented set of spends** (so a harvested shard cannot permanently DoS the signature).

> This is **not** a post-quantum Bitcoin *payment* signature (unlike QSB/Heilman). Consensus does not bind branches to the spending transaction. Copied witnesses can move value to other outputs; the detached message stays the same.
>
> Consensus-bound spending without a soft fork needs `CHECKSIG` as a sighash oracle plus a way to amplify one hash-to-sig puzzle into a strong binding. Binohash/QSB do that with legacy `FindAndDelete` on `CHECKMULTISIG` — a nonce space invisible to pinning and controllable only through preimage-committed choices. SegWit v0 has `OP_CODESEPARATOR` position (~2^7 candidates) and nothing else; input sets and sequences are attacker-controllable, and every other field is visible to pinning. Sharding cannot add bits: per-output security equals that output's own script. QSB remains the spending counterpart (legacy bare script, non-standard). UTXO-OTS stays on the seal side. Copied witnesses, as a limitation for payments, are the desired property for a seal: they republish the owner's transition.

## Seal-asset v0 (Phase A)

A funded bank is a hash-only single-use seal. The closing message is the opened branch vector. `seal-asset v0` is a toy RGB-shaped asset on that seal: genesis, transfer, consignment, resolver. See [TECHNICAL_NOTE.md](TECHNICAL_NOTE.md) and [RESEARCH_PLAN_V2.md](RESEARCH_PLAN_V2.md).

```bash
cargo test --manifest-path implementation/Cargo.toml
./scripts/regtest_seal_demo.sh    # issue → transfer → attacker copy → resolve
```

The demo funds three banks, issues to A, transfers A → B, lets an attacker confirm a copied witness paying themselves, and still resolves the asset to B.

## Quick demo (regtest)

```bash
# Bitcoin Core + Rust required
./scripts/regtest_demo.sh
```

That mines coins, funds 12 shards, builds a publication tx, runs `testmempoolaccept`, broadcasts, and verifies.

Manual library path:

```bash
cd implementation
cargo test
cargo run -- keygen --master <hex> --network regtest
```

## What works today

| Piece | Status |
| --- | --- |
| Radix-4 P2WSH digit scripts (2305 B / 192 ops) | yes |
| Setup + aggregate publication | yes |
| Fragmented set-of-spends + harvest completion | yes |
| `libbitcoinconsensus` + Core `testmempoolaccept` | yes |
| Bank state machine (expose-before-sign) | yes |
| Copied-witness / mutated-output tests | yes |
| Seal-asset v0 (genesis, transfer, resolver, adversarial programme) | yes |
| Formal security reductions / paper | later |

## Security model (three properties)

1. **Cryptographic unforgeability** — Lamport-style; hash assumptions only.
2. **Chain-relative uniqueness** — single-use seals / UTXO spend-once (Todd/RGB prior art).
3. **Publication liveness** — fragmented completion after subset witness harvesting.

Do not collapse these. Seals do not erase conflicting preimages leaked off-chain.

## Repo layout

```
RESEARCH_PLAN.md           research program + gates
RESEARCH_PLAN_V2.md        hash-only seal application (Phase A)
TECHNICAL_NOTE.md          seal mapping, adversarial results, measurements
phase0/                    novelty memo, script accounting, security model
implementation/            Rust crate + CLI
scripts/regtest_demo.sh
scripts/regtest_seal_demo.sh
artifacts/                 local demo outputs (gitignored node datadir)
```


## License

MIT. Experimental software — do not put meaningful mainnet value under it until you have reviewed the state machine and adversarial tests yourself.
