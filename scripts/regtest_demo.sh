#!/usr/bin/env bash
# One-command regtest demo: fund setup shards, publish a detached-message signature.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATADIR="${STS_DATADIR:-$ROOT/artifacts/regtest/bitcoincore}"
ART="$ROOT/artifacts/regtest"
MASTER="${STS_MASTER:-00112233445566778899aabbccddeeff}"
SHARD_SATS="${STS_SHARD_SATS:-10000}"
MSG="${STS_MESSAGE:-spend-to-sign open-source demo}"

mkdir -p "$ART" "$DATADIR"
cd "$ROOT/implementation"

need() { command -v "$1" >/dev/null || { echo "missing $1"; exit 1; }; }
need bitcoind
need bitcoin-cli
need cargo
need python3
need jq

rpc() { bitcoin-cli -regtest -datadir="$DATADIR" "$@"; }

if ! rpc -getinfo >/dev/null 2>&1; then
  echo "starting bitcoind -regtest…"
  bitcoind -regtest -datadir="$DATADIR" -daemon -fallbackfee=0.0002
  for i in $(seq 1 30); do
    rpc -getinfo >/dev/null 2>&1 && break
    sleep 0.3
  done
fi

rpc createwallet "sts" >/dev/null 2>&1 || rpc loadwallet "sts" >/dev/null 2>&1 || true

BAL=$(rpc getbalances | jq -r '.mine.trusted')
if python3 -c "import sys; sys.exit(0 if float('$BAL') < 1 else 1)"; then
  ADDR=$(rpc getnewaddress)
  echo "mining to $ADDR…"
  rpc generatetoaddress 101 "$ADDR" >/dev/null
fi

FUND_ADDR=$(rpc getnewaddress)
# 12*shard + fee headroom
FUND_BTC=$(python3 -c "print(f'{(${SHARD_SATS}*12 + 5000)/1e8:.8f}')")
FUND_SEND=$(rpc sendtoaddress "$FUND_ADDR" "$FUND_BTC")
rpc generatetoaddress 1 "$(rpc getnewaddress)" >/dev/null

UNSPENT=$(rpc listunspent 1 9999999 "[\"$FUND_ADDR\"]")
FUNDING_TXID=$(printf '%s' "$UNSPENT" | python3 -c 'import sys,json; print(json.load(sys.stdin)[0]["txid"])')
FUNDING_VOUT=$(printf '%s' "$UNSPENT" | python3 -c 'import sys,json; print(json.load(sys.stdin)[0]["vout"])')
FUNDING_SATS=$(printf '%s' "$UNSPENT" | python3 -c 'import sys,json; print(int(round(json.load(sys.stdin)[0]["amount"]*1e8)))')

cargo build --quiet
cargo run --quiet -- setup \
  --master "$MASTER" \
  --funding-txid "$FUNDING_TXID" \
  --funding-vout "$FUNDING_VOUT" \
  --funding-sats "$FUNDING_SATS" \
  --shard-sats "$SHARD_SATS" \
  --fee-sats 1000 \
  --out "$ART/setup.unsigned.hex"

UNSIGNED=$(tr -d '\n' < "$ART/setup.unsigned.hex")
SIGNED=$(rpc signrawtransactionwithwallet "$UNSIGNED")
HEX=$(printf '%s' "$SIGNED" | jq -r .hex)
COMPLETE=$(printf '%s' "$SIGNED" | jq -r .complete)
test "$COMPLETE" = "true"
printf '%s\n' "$HEX" > "$ART/setup.signed.hex"
SETUP_TXID=$(rpc sendrawtransaction "$HEX")
printf '%s\n' "$SETUP_TXID" > "$ART/setup.txid"
rpc generatetoaddress 1 "$(rpc getnewaddress)" >/dev/null
echo "setup_txid=$SETUP_TXID"

cargo run --quiet -- sign \
  --master "$MASTER" \
  --setup-txid "$SETUP_TXID" \
  --first-vout 0 \
  --shard-sats "$SHARD_SATS" \
  --network regtest \
  --message "$MSG" \
  --out "$ART/sign.tx"

SIGN_HEX=$(tr -d '\n' < "$ART/sign.tx")
ACCEPT=$(rpc testmempoolaccept "[\"$SIGN_HEX\"]")
echo "$ACCEPT" | tee "$ART/testmempoolaccept.json" >/dev/null
ALLOWED=$(printf '%s' "$ACCEPT" | jq -r '.[0].allowed')
test "$ALLOWED" = "true"

PUB_TXID=$(rpc sendrawtransaction "$SIGN_HEX")
printf '%s\n' "$PUB_TXID" > "$ART/sign.txid"
printf '%s\n' "$MSG" > "$ART/sign.message"
rpc generatetoaddress 1 "$(rpc getnewaddress)" >/dev/null

cargo run --quiet -- verify \
  --master "$MASTER" \
  --setup-txid "$SETUP_TXID" \
  --first-vout 0 \
  --shard-sats "$SHARD_SATS" \
  --network regtest \
  --message "$MSG" \
  --tx "$ART/sign.tx"

echo
echo "OK  message: $MSG"
echo "    setup:   $SETUP_TXID"
echo "    publish: $PUB_TXID"
echo "    (regtest only — not mainnet)"
