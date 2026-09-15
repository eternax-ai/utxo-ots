#!/usr/bin/env bash
# Issue → transfer → attacker copy → resolve (seal-asset v0).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATADIR="${UTXO_OTS_DATADIR:-$ROOT/artifacts/regtest/bitcoincore}"
ART="$ROOT/artifacts/seals"
MASTER="${UTXO_OTS_MASTER:-00112233445566778899aabbccddeeff}"
SHARD_SATS="${UTXO_OTS_SHARD_SATS:-10000}"
SUPPLY="${UTXO_OTS_SUPPLY:-1000000}"
G_NONCE="01000000000000000000000000000000"
A_NONCE="02000000000000000000000000000000"
B_NONCE="03000000000000000000000000000000"

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
if python3 -c "import sys; sys.exit(0 if float('$BAL') < 5 else 1)"; then
  ADDR=$(rpc getnewaddress)
  echo "mining to $ADDR…"
  rpc generatetoaddress 101 "$ADDR" >/dev/null
fi

cargo build --quiet

fund_setup() {
  local nonce="$1"
  local stem="$2"
  local fund_addr fund_btc fund_send unspent funding_txid funding_vout funding_sats
  local unsigned signed hex complete setup_txid
  fund_addr=$(rpc getnewaddress)
  fund_btc=$(python3 -c "print(f'{(${SHARD_SATS}*12 + 5000)/1e8:.8f}')")
  fund_send=$(rpc sendtoaddress "$fund_addr" "$fund_btc")
  rpc generatetoaddress 1 "$(rpc getnewaddress)" >/dev/null
  unspent=$(rpc listunspent 1 9999999 "[\"$fund_addr\"]")
  funding_txid=$(printf '%s' "$unspent" | python3 -c 'import sys,json; print(json.load(sys.stdin)[0]["txid"])')
  funding_vout=$(printf '%s' "$unspent" | python3 -c 'import sys,json; print(json.load(sys.stdin)[0]["vout"])')
  funding_sats=$(printf '%s' "$unspent" | python3 -c 'import sys,json; print(int(round(json.load(sys.stdin)[0]["amount"]*1e8)))')

  cargo run --quiet -- setup \
    --master "$MASTER" \
    --key-nonce "$nonce" \
    --funding-txid "$funding_txid" \
    --funding-vout "$funding_vout" \
    --funding-sats "$funding_sats" \
    --shard-sats "$SHARD_SATS" \
    --fee-sats 1000 \
    --out "$ART/${stem}.setup.unsigned.hex"

  unsigned=$(tr -d '\n' < "$ART/${stem}.setup.unsigned.hex")
  signed=$(rpc signrawtransactionwithwallet "$unsigned")
  hex=$(printf '%s' "$signed" | jq -r .hex)
  complete=$(printf '%s' "$signed" | jq -r .complete)
  test "$complete" = "true"
  printf '%s\n' "$hex" > "$ART/${stem}.setup.hex"
  setup_txid=$(rpc sendrawtransaction "$hex")
  printf '%s\n' "$setup_txid" > "$ART/${stem}.setup.txid"
  rpc generatetoaddress 1 "$(rpc getnewaddress)" >/dev/null
  echo "${stem}_setup_txid=$setup_txid"
}

echo "== funding banks G, A, B =="
fund_setup "$G_NONCE" g
fund_setup "$A_NONCE" a
fund_setup "$B_NONCE" b

G_TXID=$(tr -d '\n' < "$ART/g.setup.txid")
A_TXID=$(tr -d '\n' < "$ART/a.setup.txid")
B_TXID=$(tr -d '\n' < "$ART/b.setup.txid")

echo "== genesis G → A =="
cargo run --quiet -- seal-genesis \
  --master "$MASTER" \
  --key-nonce "$G_NONCE" \
  --setup-txid "$G_TXID" \
  --holder-setup-txid "$A_TXID" \
  --supply "$SUPPLY" \
  --shard-sats "$SHARD_SATS" \
  --network regtest \
  --consignment "$ART/genesis.json" \
  --out "$ART/genesis.tx"

GENESIS_HEX=$(tr -d '\n' < "$ART/genesis.tx")
test "$(rpc testmempoolaccept "[\"$GENESIS_HEX\"]" | jq -r '.[0].allowed')" = "true"
GENESIS_TXID=$(rpc sendrawtransaction "$GENESIS_HEX")
rpc generatetoaddress 1 "$(rpc getnewaddress)" >/dev/null
echo "genesis_publish=$GENESIS_TXID"

echo "== transfer A → B =="
cargo run --quiet -- seal-transfer \
  --master "$MASTER" \
  --key-nonce "$A_NONCE" \
  --setup-txid "$A_TXID" \
  --consignment-in "$ART/genesis.json" \
  --receiver-setup-txid "$B_TXID" \
  --amount "$SUPPLY" \
  --shard-sats "$SHARD_SATS" \
  --network regtest \
  --consignment-out "$ART/transfer.json" \
  --out "$ART/transfer.tx"

echo "== attacker copies A's witness into a different carrier =="
cargo run --quiet -- seal-copy-attack \
  --tx "$ART/transfer.tx" \
  --out "$ART/attack.tx"

ATTACK_HEX=$(tr -d '\n' < "$ART/attack.tx")
test "$(rpc testmempoolaccept "[\"$ATTACK_HEX\"]" | jq -r '.[0].allowed')" = "true"
ATTACK_TXID=$(rpc sendrawtransaction "$ATTACK_HEX")
rpc generatetoaddress 1 "$(rpc getnewaddress)" >/dev/null
echo "attack_publish=$ATTACK_TXID"

# Honest original conflicts and must not confirm.
if rpc sendrawtransaction "$(tr -d '\n' < "$ART/transfer.tx")" >/dev/null 2>&1; then
  echo "unexpected: honest transfer confirmed after attacker copy"
  exit 1
fi

echo "== resolve (confirmed attacker carrier) =="
RESOLVE=$(cargo run --quiet -- seal-resolve \
  --consignment "$ART/transfer.json" \
  --setup-tx "$ART/g.setup.hex" \
  --setup-tx "$ART/a.setup.hex" \
  --setup-tx "$ART/b.setup.hex" \
  --confirmed-tx "$ART/genesis.tx" \
  --confirmed-tx "$ART/attack.tx" \
  --min-confirmations 1)
printf '%s\n' "$RESOLVE"
echo "$RESOLVE" | grep -q "status=Open"
echo "$RESOLVE" | grep -q "$B_TXID"

echo
echo "OK  seal-asset v0: issue G→A, transfer A→B, attacker copy still resolves to B"
echo "    genesis: $GENESIS_TXID"
echo "    attack:  $ATTACK_TXID"
echo "    (regtest only — not mainnet)"
