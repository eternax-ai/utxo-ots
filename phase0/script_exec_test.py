#!/usr/bin/env python3
"""Executable check of the radix-4 P2WSH digit template.

Proves:
  - each of the four selector paths opens the matching commitment;
  - mismatched preimage/selector pairs fail EQUALVERIFY;
  - 16-digit shard scripts require witness digits in reverse index order
    (digit 15 at stack bottom … digit 0 at stack top), each as
    <preimage> <lowBit> <highBit> with highBit consumed first.
"""

from __future__ import annotations

import hashlib
import sys

from script_accounting import (
    OP_ELSE,
    OP_ENDIF,
    OP_EQUALVERIFY,
    OP_IF,
    OP_SHA256,
    OP_SWAP,
    OP_TRUE,
    digit_script,
    shard_script,
)


def _cast_bool(v: bytes) -> bool:
    return v not in (b"", b"\x00")


def exec_template(script: bytes, stack_init: list[bytes]) -> list[bytes]:
    """Minimal interpreter sufficient for the Spend-to-Sign digit template."""
    stack = [bytes(x) for x in stack_init]
    i = 0
    branch: list[dict] = []

    def executing() -> bool:
        return all(b["active"] for b in branch) if branch else True

    while i < len(script):
        op = script[i]
        i += 1
        if op == OP_TRUE:
            if executing():
                stack.append(b"\x01")
            continue
        if 1 <= op <= 75:
            data = script[i : i + op]
            i += op
            if executing():
                stack.append(data)
            continue
        if op == OP_IF:
            if executing():
                if not stack:
                    raise RuntimeError("IF on empty stack")
                cond = _cast_bool(stack.pop())
                branch.append({"active": cond, "then_taken": cond})
            else:
                branch.append({"active": False, "then_taken": False, "skip": True})
            continue
        if op == OP_ELSE:
            if not branch:
                raise RuntimeError("ELSE without IF")
            b = branch[-1]
            if b.get("skip"):
                continue
            parent_ok = all(x["active"] for x in branch[:-1]) if len(branch) > 1 else True
            b["active"] = (not b["then_taken"]) if parent_ok else False
            continue
        if op == OP_ENDIF:
            if not branch:
                raise RuntimeError("ENDIF without IF")
            branch.pop()
            continue
        if not executing():
            continue
        if op == OP_SWAP:
            stack[-1], stack[-2] = stack[-2], stack[-1]
            continue
        if op == OP_SHA256:
            stack.append(hashlib.sha256(stack.pop()).digest())
            continue
        if op == OP_EQUALVERIFY:
            a, b = stack.pop(), stack.pop()
            if a != b:
                raise RuntimeError("EQUALVERIFY failed")
            continue
        raise RuntimeError(f"unhandled opcode {op:#x}")

    if branch:
        raise RuntimeError("unbalanced IF")
    return stack


def bool_el(bit: int) -> bytes:
    return b"\x01" if bit else b""


def make_bank(digits: int = 16):
    secrets = [
        [hashlib.sha256(b"spend-to-sign/test" + bytes([i, j])).digest() for j in range(4)]
        for i in range(digits)
    ]
    commits = [[hashlib.sha256(s).digest() for s in row] for row in secrets]
    return secrets, commits


def witness_for(secrets, digits_vec, *, reverse_digits: bool = True) -> list[bytes]:
    n = len(digits_vec)
    order = range(n - 1, -1, -1) if reverse_digits else range(n)
    items: list[bytes] = []
    for i in order:
        d = digits_vec[i]
        items.extend([secrets[i][d], bool_el(d & 1), bool_el((d >> 1) & 1)])
    return items


def main() -> int:
    # One-digit exhaustive paths
    secrets1, commits1 = make_bank(1)
    dscript = digit_script(commits1[0])
    for d in range(4):
        stack = exec_template(dscript, witness_for(secrets1, [d]))
        assert stack == [], stack
        for wrong in range(4):
            if wrong == d:
                continue
            bad = [secrets1[0][wrong], bool_el(d & 1), bool_el((d >> 1) & 1)]
            try:
                exec_template(dscript, bad)
                raise AssertionError(f"digit {d} accepted wrong preimage {wrong}")
            except RuntimeError as e:
                assert "EQUALVERIFY" in str(e)

    # 16-digit shard
    secrets, commits = make_bank(16)
    script = shard_script(commits)
    for digits_vec in (
        [0] * 16,
        [3] * 16,
        [(i * 3) % 4 for i in range(16)],
        [0, 1, 2, 3] * 4,
    ):
        stack = exec_template(script, witness_for(secrets, digits_vec, reverse_digits=True))
        assert stack == [b"\x01"], stack

    try:
        exec_template(script, witness_for(secrets, [0] * 16, reverse_digits=False))
        raise AssertionError("forward digit order should fail")
    except RuntimeError:
        pass

    print("SCRIPT_EXEC_OK")
    print("stack_order=witness digits 15..0 as <preimage><lowBit><highBit>")
    return 0


if __name__ == "__main__":
    sys.exit(main())
