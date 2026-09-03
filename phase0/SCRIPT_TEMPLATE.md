# Hand-checked Script template

## Digit fragment (radix 4)

Expected stack before each digit fragment (bottom → top):

```text
<preimage> <lowBit> <highBit>
```

`highBit` is consumed by the outer `OP_IF`, `lowBit` by the inner `OP_IF`.

```text
OP_IF
    OP_IF <c3> OP_ELSE <c2> OP_ENDIF
OP_ELSE
    OP_IF <c1> OP_ELSE <c0> OP_ENDIF
OP_ENDIF
OP_SWAP
OP_SHA256
OP_EQUALVERIFY
```

| high | low | digit | commitment |
| --- | --- | --- | --- |
| 0 | 0 | 0 | c0 |
| 0 | 1 | 1 | c1 |
| 1 | 0 | 2 | c2 |
| 1 | 1 | 3 | c3 |

Boolean witness encodings: false = empty item `0x`; true = `0x01`.

Per digit: 132 commitment push bytes + 12 counted opcodes = 144 serialized bytes.

## Shard script

Concatenate 16 digit fragments, then `OP_TRUE` (`OP_1`, not counted toward the
201-opcode limit).

Measured (`script_accounting.py`):

| metric | value | limit | headroom |
| --- | --- | --- | --- |
| script size | 2305 B | 3600 B policy | 1295 |
| counted opcodes | 192 | 201 consensus | 9 |
| witness stack items | 48 | 100 policy | 52 |
| max item size | 32 B | 80 B policy | 48 |

**Binding constraint:** opcodes. 17 digits × 12 ops = 204 > 201.

## Witness stack order (derived from execution tests)

The script evaluates digit 0 first, then digit 1, …, digit 15. Each fragment
consumes three items from the **top** of the stack. Therefore the witness
pushes digits in **reverse index order**:

```text
# first pushed = stack bottom; last pushed = stack top
for i in 15, 14, ..., 0:
    push preimage_i
    push lowBit_i
    push highBit_i
push witnessScript
```

`script_exec_test.py` checks all four one-digit paths, mismatched preimages,
and the 16-digit reverse-order rule.

## Aggregate weight (serializer estimate)

12 shards, one `OP_RETURN` output, average half-byte selectors:
**36 670 weight / 9 168 vB**, under the 400 000 WU standard limit. Bitcoin Core
`testmempoolaccept` remains the Phase 1 oracle.
