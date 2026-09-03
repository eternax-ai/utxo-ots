//! Radix-4 nested-IF P2WSH digit scripts.

use bitcoin::ScriptBuf;
use bitcoin::opcodes::all::{
    OP_ELSE, OP_ENDIF, OP_EQUALVERIFY, OP_IF, OP_PUSHNUM_1, OP_SHA256, OP_SWAP,
};
use bitcoin::script::PushBytesBuf;

use crate::error::Error;
use crate::parameters::{
    ALTERNATIVES, DIGITS_PER_SHARD, MAX_OPS_PER_SCRIPT, MAX_STANDARD_P2WSH_SCRIPT_SIZE,
    MAX_STANDARD_P2WSH_STACK_ITEM_SIZE, MAX_STANDARD_P2WSH_STACK_ITEMS,
};

/// One physical shard: witness script + standardness metrics.
#[derive(Debug, Clone)]
pub struct ShardScript {
    pub script: ScriptBuf,
    pub script_size: usize,
    pub counted_opcodes: usize,
    pub witness_stack_items: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct ShardMetrics {
    pub script_size: usize,
    pub counted_opcodes: usize,
    pub witness_stack_items: usize,
    pub max_item_size: usize,
    pub script_ok: bool,
    pub opcode_ok: bool,
    pub stack_ok: bool,
    pub item_ok: bool,
}

/// Append one digit's IF-tree + SHA256 EQUALVERIFY.
fn push_digit(builder: bitcoin::script::Builder, commitments: &[[u8; 32]; ALTERNATIVES]) -> bitcoin::script::Builder {
    let c0 = PushBytesBuf::try_from(commitments[0].to_vec()).expect("32 bytes");
    let c1 = PushBytesBuf::try_from(commitments[1].to_vec()).expect("32 bytes");
    let c2 = PushBytesBuf::try_from(commitments[2].to_vec()).expect("32 bytes");
    let c3 = PushBytesBuf::try_from(commitments[3].to_vec()).expect("32 bytes");

    // OP_IF
    //   OP_IF <c3> OP_ELSE <c2> OP_ENDIF
    // OP_ELSE
    //   OP_IF <c1> OP_ELSE <c0> OP_ENDIF
    // OP_ENDIF
    // OP_SWAP OP_SHA256 OP_EQUALVERIFY
    builder
        .push_opcode(OP_IF)
        .push_opcode(OP_IF)
        .push_slice(c3)
        .push_opcode(OP_ELSE)
        .push_slice(c2)
        .push_opcode(OP_ENDIF)
        .push_opcode(OP_ELSE)
        .push_opcode(OP_IF)
        .push_slice(c1)
        .push_opcode(OP_ELSE)
        .push_slice(c0)
        .push_opcode(OP_ENDIF)
        .push_opcode(OP_ENDIF)
        .push_opcode(OP_SWAP)
        .push_opcode(OP_SHA256)
        .push_opcode(OP_EQUALVERIFY)
}

/// Count non-push opcodes the way Bitcoin Core does (`opcode > OP_16`).
pub fn count_ops(script: &ScriptBuf) -> usize {
    let mut ops = 0usize;
    for instruction in script.instructions() {
        let Ok(inst) = instruction else {
            continue;
        };
        match inst {
            bitcoin::script::Instruction::Op(op) => {
                // OP_16 = 0x60. Counted if > OP_16.
                if op.to_u8() > 0x60 {
                    ops += 1;
                }
            }
            bitcoin::script::Instruction::PushBytes(_) => {}
        }
    }
    ops
}

pub fn build_shard_script(
    digit_commitments: &[[[u8; 32]; ALTERNATIVES]],
) -> Result<ShardScript, Error> {
    if digit_commitments.len() != DIGITS_PER_SHARD {
        return Err(Error::InvalidParameter("expected 16 digits per shard"));
    }
    let mut builder = bitcoin::script::Builder::new();
    for row in digit_commitments {
        builder = push_digit(builder, row);
    }
    builder = builder.push_opcode(OP_PUSHNUM_1);
    let script = builder.into_script();
    let counted_opcodes = count_ops(&script);
    let script_size = script.len();
    // 16 digits × (1 preimage + 2 selectors)
    let witness_stack_items = DIGITS_PER_SHARD * 3;
    Ok(ShardScript {
        script,
        script_size,
        counted_opcodes,
        witness_stack_items,
    })
}

pub fn shard_metrics(shard: &ShardScript) -> ShardMetrics {
    ShardMetrics {
        script_size: shard.script_size,
        counted_opcodes: shard.counted_opcodes,
        witness_stack_items: shard.witness_stack_items,
        max_item_size: 32,
        script_ok: shard.script_size <= MAX_STANDARD_P2WSH_SCRIPT_SIZE,
        opcode_ok: shard.counted_opcodes <= MAX_OPS_PER_SCRIPT,
        stack_ok: shard.witness_stack_items <= MAX_STANDARD_P2WSH_STACK_ITEMS,
        item_ok: 32 <= MAX_STANDARD_P2WSH_STACK_ITEM_SIZE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn fake_commits() -> Vec<[[u8; 32]; 4]> {
        (0..16)
            .map(|i| {
                let mut row = [[0u8; 32]; 4];
                for j in 0..4 {
                    row[j] = Sha256::digest([i as u8, j as u8]).into();
                }
                row
            })
            .collect()
    }

    #[test]
    fn reference_shard_metrics() {
        let commits = fake_commits();
        let shard = build_shard_script(&commits).unwrap();
        assert_eq!(shard.script_size, 2305);
        assert_eq!(shard.counted_opcodes, 192);
        assert_eq!(shard.witness_stack_items, 48);
        let m = shard_metrics(&shard);
        assert!(m.script_ok && m.opcode_ok && m.stack_ok && m.item_ok);
    }
}
