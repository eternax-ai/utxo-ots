# Tweet drafts

## Short

UTXO-OTS: post-quantum *attestations* on Bitcoin today — standard P2WSH shards, SHA-256 hashlocks only, no soft fork.

Not a PQ payment signature (consensus doesn’t bind the message). It *is* a ledger-finalized one-time hash signature with fragmented publication so witness harvesting can’t permanently kill it.

Regtest demo + Rust impl: https://github.com/eternax-ai/utxo-ots

## Slightly longer

We open-sourced UTXO-OTS.

Idea: put a generalized Lamport one-time key in 12 native P2WSH outputs. Spend them to reveal branch preimages. Bitcoin checks openings; an overlay checks the message digest.

- no CHECKSIG / no new opcodes
- ~9 kb vB aggregate publication
- set-of-spends survives single-shard harvest DoS
- explicitly *not* QSB-style payment auth

Single-use seals aren’t new (Todd/RGB). The thing we’re shipping is the concrete P2WSH composition + measurements + state/adversarial harness.

`./scripts/regtest_demo.sh`
https://github.com/eternax-ai/utxo-ots

## Disclaimer line (pin or reply)

Does not protect Bitcoin outputs. Copied witnesses can pay elsewhere; only the detached attestation is what verifiers should trust.
