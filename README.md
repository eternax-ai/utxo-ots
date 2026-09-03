# UTXO-OTS

**Bitcoin-ledger-finalized one-time signatures using only SHA-256 hashlocks and standard P2WSH — no new opcodes, no `CHECKSIG`, no soft fork.**

You create 12 native P2WSH outputs (the public key). To sign a message, you spend them and reveal one preimage per digest digit. Bitcoin consensus checks the openings; an external verifier checks that the branch vector encodes the message. Publication can be one aggregate transaction or a **fragmented set of spends** (so a harvested shard cannot permanently DoS the signature).

> This is **not** a post-quantum Bitcoin *payment* signature (unlike QSB/Heilman). Consensus does not bind branches to the spending transaction. Copied witnesses can move value to other outputs; the detached message stays the same.

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
| Formal security reductions / paper | later |

## Security model (three properties)

1. **Cryptographic unforgeability** — Lamport-style; hash assumptions only.
2. **Chain-relative uniqueness** — single-use seals / UTXO spend-once (Todd/RGB prior art).
3. **Publication liveness** — fragmented completion after subset witness harvesting.

Do not collapse these. Seals do not erase conflicting preimages leaked off-chain.

## Repo layout

```
RESEARCH_PLAN.md     research program + gates
phase0/              novelty memo, script accounting, security model
implementation/      Rust crate + CLI
scripts/regtest_demo.sh
artifacts/           local demo outputs (gitignored node datadir)
```

## Tweet / one-liner

See [`TWEET.md`](./TWEET.md).

## License

MIT. Experimental software — do not put meaningful mainnet value under it until you have reviewed the state machine and adversarial tests yourself.
