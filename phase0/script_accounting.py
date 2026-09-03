#!/usr/bin/env python3
"""Exact P2WSH resource accounting for UTXO-OTS digit shards.

Serializes the nested-IF commitment tree from RESEARCH_PLAN.md and reports
consensus/policy metrics. No Bitcoin Core dependency: byte layout matches
Bitcoin Script push encoding (direct push for 1..75 byte payloads).

Limits (Bitcoin Core policy / consensus):
  MAX_OPS_PER_SCRIPT                 = 201   (consensus)
  MAX_STANDARD_P2WSH_SCRIPT_SIZE     = 3600  (policy)
  MAX_STANDARD_P2WSH_STACK_ITEMS     = 100   (policy; excludes witnessScript)
  MAX_STANDARD_P2WSH_STACK_ITEM_SIZE = 80    (policy)
  MAX_STANDARD_TX_WEIGHT             = 400000
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import List, Sequence, Tuple

OP_IF = 0x63
OP_NOTIF = 0x64
OP_ELSE = 0x67
OP_ENDIF = 0x68
OP_VERIFY = 0x69
OP_TOALTSTACK = 0x6B
OP_FROMALTSTACK = 0x6C
OP_DROP = 0x75
OP_DUP = 0x76
OP_SWAP = 0x7C
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_SHA256 = 0xA8
OP_HASH256 = 0xAA
OP_TRUE = 0x51  # OP_1; push opcode, does NOT increment nOpCount

MAX_OPS_PER_SCRIPT = 201
MAX_STANDARD_P2WSH_SCRIPT_SIZE = 3600
MAX_STANDARD_P2WSH_STACK_ITEMS = 100
MAX_STANDARD_P2WSH_STACK_ITEM_SIZE = 80
MAX_STANDARD_TX_WEIGHT = 400_000
P2WSH_DUST_SATS = 330


def push_bytes(data: bytes) -> bytes:
    n = len(data)
    if n == 0:
        return bytes([0x00])  # OP_0
    if n <= 75:
        return bytes([n]) + data
    raise ValueError(f"payload too large for direct push: {n}")


def is_counted_opcode(op: int) -> bool:
    # Bitcoin Core: if (opcode > OP_16 && ++nOpCount > MAX_OPS_PER_SCRIPT)
    return op > 0x60  # OP_16 == 0x60


def count_ops(script: bytes) -> int:
    i = 0
    ops = 0
    while i < len(script):
        op = script[i]
        i += 1
        if op == 0x00:
            continue
        if 1 <= op <= 75:
            i += op
            continue
        if op == 0x4C:  # OP_PUSHDATA1
            n = script[i]
            i += 1 + n
            continue
        if op == 0x4D:
            n = int.from_bytes(script[i : i + 2], "little")
            i += 2 + n
            continue
        if op == 0x4E:
            n = int.from_bytes(script[i : i + 4], "little")
            i += 4 + n
            continue
        if is_counted_opcode(op):
            ops += 1
    return ops


def digit_script(commitments: Sequence[bytes]) -> bytes:
    """Four-way nested IF selecting c0..c3; then SHA256-EQUALVERIFY preimage.

    Expected initial stack (bottom -> top): <preimage> <lowBit> <highBit>
    """
    if len(commitments) != 4:
        raise ValueError("need exactly four 32-byte commitments")
    c0, c1, c2, c3 = commitments
    for c in commitments:
        if len(c) != 32:
            raise ValueError("commitments must be 32 bytes")

    # OP_IF
    #   OP_IF <c3> OP_ELSE <c2> OP_ENDIF
    # OP_ELSE
    #   OP_IF <c1> OP_ELSE <c0> OP_ENDIF
    # OP_ENDIF
    # OP_SWAP OP_SHA256 OP_EQUALVERIFY
    return b"".join(
        [
            bytes([OP_IF]),
            bytes([OP_IF]),
            push_bytes(c3),
            bytes([OP_ELSE]),
            push_bytes(c2),
            bytes([OP_ENDIF]),
            bytes([OP_ELSE]),
            bytes([OP_IF]),
            push_bytes(c1),
            bytes([OP_ELSE]),
            push_bytes(c0),
            bytes([OP_ENDIF]),
            bytes([OP_ENDIF]),
            bytes([OP_SWAP]),
            bytes([OP_SHA256]),
            bytes([OP_EQUALVERIFY]),
        ]
    )


def shard_script(all_commitments: Sequence[Sequence[bytes]], trailing_true: bool = True) -> bytes:
    body = b"".join(digit_script(cs) for cs in all_commitments)
    if trailing_true:
        body += bytes([OP_TRUE])
    return body


@dataclass(frozen=True)
class ShardMetrics:
    digits_per_shard: int
    alternatives: int
    script_size: int
    counted_opcodes: int
    witness_stack_items: int  # excluding witnessScript
    max_witness_item_size: int
    script_size_ok: bool
    opcode_ok: bool
    stack_items_ok: bool
    item_size_ok: bool
    opcode_headroom: int
    script_headroom: int
    stack_headroom: int


@dataclass(frozen=True)
class ParameterSetMetrics:
    digest_bits: int
    radix: int
    logical_digits: int
    digits_per_shard: int
    shard_count: int
    shard: ShardMetrics
    # Aggregate publication (one tx, all shards, one OP_RETURN output)
    approx_witness_bytes: int
    approx_base_bytes: int
    approx_weight: int
    approx_vbytes: int
    weight_ok: bool
    # Fee capacity under equal shard values
    dust_per_shard_sats: int
    min_total_setup_sats: int


def fake_commitments(digits: int, alternatives: int, seed: bytes = b"utxo-ots") -> List[List[bytes]]:
    out: List[List[bytes]] = []
    for i in range(digits):
        row = []
        for j in range(alternatives):
            row.append(hashlib.sha256(seed + i.to_bytes(2, "big") + bytes([j])).digest())
        out.append(row)
    return out


def measure_shard(digits_per_shard: int, alternatives: int = 4) -> ShardMetrics:
    commits = fake_commitments(digits_per_shard, alternatives)
    script = shard_script(commits)
    # Witness data items: per digit, one 32-byte preimage + log2(alternatives) selector bytes
    # For radix 4: two Boolean selectors (minimally encoded as empty / OP_1 in script,
    # but as witness stack elements they are 0-byte and 1-byte).
    import math

    selector_bits = int(math.log2(alternatives))
    items = digits_per_shard * (1 + selector_bits)
    # Worst-case item size among data items: 32-byte preimage
    max_item = 32
    ops = count_ops(script)
    return ShardMetrics(
        digits_per_shard=digits_per_shard,
        alternatives=alternatives,
        script_size=len(script),
        counted_opcodes=ops,
        witness_stack_items=items,
        max_witness_item_size=max_item,
        script_size_ok=len(script) <= MAX_STANDARD_P2WSH_SCRIPT_SIZE,
        opcode_ok=ops <= MAX_OPS_PER_SCRIPT,
        stack_items_ok=items <= MAX_STANDARD_P2WSH_STACK_ITEMS,
        item_size_ok=max_item <= MAX_STANDARD_P2WSH_STACK_ITEM_SIZE,
        opcode_headroom=MAX_OPS_PER_SCRIPT - ops,
        script_headroom=MAX_STANDARD_P2WSH_SCRIPT_SIZE - len(script),
        stack_headroom=MAX_STANDARD_P2WSH_STACK_ITEMS - items,
    )


def estimate_aggregate_weight(
    shard: ShardMetrics,
    shard_count: int,
    *,
    avg_selector_bytes_per_digit: float = 0.5,
) -> Tuple[int, int, int, int]:
    """Rough weight model for one aggregate publication tx.

    Witness per shard (exact structure, approximate selector sizes):
      - digits * (32-byte preimage + selector_bits stack items)
      - witnessScript

    Base serialization approximates:
      version(4) + marker/flag excluded from base + vin_count + per-input
      (prevout 36 + scriptSig 1 empty + sequence 4) + vout_count + one
      OP_RETURN output (~11 bytes value+script) + locktime(4).
    SegWit marker/flag and witness are in witness weight.
    """
    import math

    selector_bits = int(math.log2(shard.alternatives))
    # CompactSize for script length
    def compact_size_len(n: int) -> int:
        if n < 0xFD:
            return 1
        if n <= 0xFFFF:
            return 3
        if n <= 0xFFFFFFFF:
            return 5
        return 9

    witness_per_shard = 0
    # stack item count + script
    stack_count = shard.witness_stack_items + 1
    witness_per_shard += compact_size_len(stack_count)
    # preimages
    for _ in range(shard.digits_per_shard):
        witness_per_shard += 1 + 32  # len + preimage
        # selectors: empty vector is 1 byte length 0; true is 1+1
        # use average
        for _ in range(selector_bits):
            witness_per_shard += 1 + avg_selector_bytes_per_digit
    witness_per_shard += compact_size_len(shard.script_size) + shard.script_size

    total_witness = int(round(witness_per_shard * shard_count))

    # Base tx
    vin = shard_count
    # OP_RETURN "" : 8 value + 1 script_len + 1 OP_RETURN = 10, sometimes +0 push
    op_return_script = bytes([0x6A])  # OP_RETURN alone
    vout_payload = 8 + 1 + len(op_return_script)
    base = (
        4  # version
        + compact_size_len(vin)
        + vin * (36 + 1 + 4)  # prevout + empty scriptSig + sequence
        + compact_size_len(1)
        + vout_payload
        + 4  # locktime
    )
    # SegWit marker+flag are witness-side for weight purposes (cost 2 weight)
    witness_with_marker = 2 + total_witness
    weight = base * 4 + witness_with_marker
    vbytes = (weight + 3) // 4
    return total_witness, base, weight, vbytes


def measure_parameter_set(
    digest_bits: int = 384,
    radix: int = 4,
    digits_per_shard: int = 16,
) -> ParameterSetMetrics:
    import math

    if radix != 4:
        raise NotImplementedError("this serializer currently encodes radix-4 trees only")
    logical_digits = digest_bits // int(math.log2(radix))
    if logical_digits % digits_per_shard != 0:
        raise ValueError("digits must divide evenly across shards for the reference profile")
    shard_count = logical_digits // digits_per_shard
    shard = measure_shard(digits_per_shard, alternatives=radix)
    wbytes, base, weight, vbytes = estimate_aggregate_weight(shard, shard_count)
    return ParameterSetMetrics(
        digest_bits=digest_bits,
        radix=radix,
        logical_digits=logical_digits,
        digits_per_shard=digits_per_shard,
        shard_count=shard_count,
        shard=shard,
        approx_witness_bytes=wbytes,
        approx_base_bytes=base,
        approx_weight=weight,
        approx_vbytes=vbytes,
        weight_ok=weight <= MAX_STANDARD_TX_WEIGHT,
        dust_per_shard_sats=P2WSH_DUST_SATS,
        min_total_setup_sats=P2WSH_DUST_SATS * shard_count,
    )


def max_digits_under_limits(alternatives: int = 4) -> dict:
    """Search maximum digits/shard for radix-4 tree under all four limits."""
    best = None
    for d in range(1, 80):
        m = measure_shard(d, alternatives=alternatives)
        ok = m.script_size_ok and m.opcode_ok and m.stack_items_ok and m.item_size_ok
        if ok:
            best = m
        else:
            break
    return asdict(best) if best else {}


def packing_table(digest_bits: int = 384) -> List[dict]:
    """Compare shard counts for feasible digits_per_shard under radix 4."""
    import math

    logical = digest_bits // 2  # log2(4)=2
    rows = []
    for d in range(1, 40):
        m = measure_shard(d)
        if not (m.script_size_ok and m.opcode_ok and m.stack_items_ok and m.item_size_ok):
            continue
        if logical % d != 0:
            # still report ceiling shards
            shards = (logical + d - 1) // d
            even = False
        else:
            shards = logical // d
            even = True
        wbytes, base, weight, vbytes = estimate_aggregate_weight(m, shards)
        rows.append(
            {
                "digits_per_shard": d,
                "even_pack": even,
                "shard_count": shards,
                "script_size": m.script_size,
                "opcodes": m.counted_opcodes,
                "stack_items": m.witness_stack_items,
                "opcode_headroom": m.opcode_headroom,
                "approx_weight": weight,
                "approx_vbytes": vbytes,
            }
        )
    return rows


def main() -> None:
    ref = measure_parameter_set()
    payload = {
        "reference_parameter_set": {
            **{k: v for k, v in asdict(ref).items() if k != "shard"},
            "shard": asdict(ref.shard),
        },
        "max_digits_per_shard_radix4": max_digits_under_limits(4),
        "packing_table_sha384_radix4": packing_table(384),
        "limits": {
            "MAX_OPS_PER_SCRIPT": MAX_OPS_PER_SCRIPT,
            "MAX_STANDARD_P2WSH_SCRIPT_SIZE": MAX_STANDARD_P2WSH_SCRIPT_SIZE,
            "MAX_STANDARD_P2WSH_STACK_ITEMS": MAX_STANDARD_P2WSH_STACK_ITEMS,
            "MAX_STANDARD_P2WSH_STACK_ITEM_SIZE": MAX_STANDARD_P2WSH_STACK_ITEM_SIZE,
            "MAX_STANDARD_TX_WEIGHT": MAX_STANDARD_TX_WEIGHT,
        },
        "per_digit_breakdown": {
            "commitment_push_bytes": 4 * 33,
            "non_push_opcodes": 12,
            "serialized_bytes": 4 * 33 + 12,
            "note": "16 digits + OP_TRUE => script_size 2305, opcodes 192",
        },
    }
    text = json.dumps(payload, indent=2)
    print(text)
    out = __file__.replace("script_accounting.py", "") + "../artifacts/benchmarks/script_accounting.json"
    # write next to phase0 as well for convenience
    local = __file__.replace("script_accounting.py", "script_accounting.json")
    with open(local, "w", encoding="utf-8") as f:
        f.write(text + "\n")
    try:
        with open(
            "/Users/dariiap/Documents/GitHub/eternax/utxo-ots/artifacts/benchmarks/script_accounting.json",
            "w",
            encoding="utf-8",
        ) as f:
            f.write(text + "\n")
    except OSError:
        pass

    # Sanity: exact sizes from plan
    m = measure_shard(16)
    assert m.script_size == 2305, m.script_size
    assert m.counted_opcodes == 192, m.counted_opcodes
    assert m.witness_stack_items == 48, m.witness_stack_items
    print("\nSANITY_OK script_size=2305 opcodes=192 stack_items=48", file=__import__("sys").stderr)


if __name__ == "__main__":
    main()
