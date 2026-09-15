# Implementation notes

See the [root README](../README.md) for the project overview,
`./scripts/regtest_demo.sh` for a detached-message signature, and
`./scripts/regtest_seal_demo.sh` for seal-asset v0.

```bash
cargo test
cargo run -- keygen --master <hex> --network regtest
cargo run -- seal-genesis --help
cargo run -- seal-transfer --help
cargo run -- seal-resolve --help
```
