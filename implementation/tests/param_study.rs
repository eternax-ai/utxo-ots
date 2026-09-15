//! Parameter-reduction measurements against Core policy limits (item 5).
//!
//! `script.rs` is frozen, so this rebuilds the radix-4 digit IF-tree locally
//! and uses the public `count_ops` oracle. Candidates that need a different
//! radix cannot reuse the production builder.

use bitcoin::opcodes::all::{
    OP_ELSE, OP_ENDIF, OP_EQUALVERIFY, OP_IF, OP_PUSHNUM_1, OP_SHA256, OP_SWAP,
};
use bitcoin::script::PushBytesBuf;
use bitcoin::ScriptBuf;
use sha2::{Digest, Sha256};
use utxo_ots::parameters::{
    MAX_OPS_PER_SCRIPT, MAX_STANDARD_P2WSH_SCRIPT_SIZE, MAX_STANDARD_P2WSH_STACK_ITEMS,
    MAX_STANDARD_P2WSH_STACK_ITEM_SIZE,
};
use utxo_ots::script::count_ops;

fn push_digit(
    builder: bitcoin::script::Builder,
    commitments: &[[u8; 32]; 4],
) -> bitcoin::script::Builder {
    let c0 = PushBytesBuf::try_from(commitments[0].to_vec()).expect("32 bytes");
    let c1 = PushBytesBuf::try_from(commitments[1].to_vec()).expect("32 bytes");
    let c2 = PushBytesBuf::try_from(commitments[2].to_vec()).expect("32 bytes");
    let c3 = PushBytesBuf::try_from(commitments[3].to_vec()).expect("32 bytes");
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

fn measure(digits: usize) -> (usize, usize, usize) {
    let mut builder = bitcoin::script::Builder::new();
    for i in 0..digits {
        let mut row = [[0u8; 32]; 4];
        for j in 0..4 {
            row[j] = Sha256::digest([i as u8, j as u8]).into();
        }
        builder = push_digit(builder, &row);
    }
    builder = builder.push_opcode(OP_PUSHNUM_1);
    let script: ScriptBuf = builder.into_script();
    let ops = count_ops(&script);
    let stack = digits * 3;
    (script.len(), ops, stack)
}

#[test]
fn radix4_digit_packing_against_limits() {
    let mut rows = Vec::new();
    for digits in 1..=17 {
        let (size, ops, stack) = measure(digits);
        let ok = ops <= MAX_OPS_PER_SCRIPT
            && size <= MAX_STANDARD_P2WSH_SCRIPT_SIZE
            && stack <= MAX_STANDARD_P2WSH_STACK_ITEMS
            && 32 <= MAX_STANDARD_P2WSH_STACK_ITEM_SIZE;
        rows.push(serde_json::json!({
            "digits_per_shard": digits,
            "script_size": size,
            "counted_opcodes": ops,
            "witness_stack_items": stack,
            "inside_limits": ok,
            "opcode_headroom": MAX_OPS_PER_SCRIPT as i32 - ops as i32,
        }));
        if digits == 16 {
            assert_eq!(size, 2305);
            assert_eq!(ops, 192);
            assert!(ok);
        }
        if digits == 17 {
            assert!(!ok, "17 digits must exceed the 201-opcode limit");
            assert!(ops > MAX_OPS_PER_SCRIPT);
        }
    }

    // SHA-256 digest, same radix-4 16-digit shards: 8 shards. Script is identical
    // to the reference shard; the saving is shard count, not per-shard policy.
    let sha256_shards = 256 / 2 / 16;
    assert_eq!(sha256_shards, 8);

    let report = serde_json::json!({
        "limits": {
            "MAX_OPS_PER_SCRIPT": MAX_OPS_PER_SCRIPT,
            "MAX_STANDARD_P2WSH_SCRIPT_SIZE": MAX_STANDARD_P2WSH_SCRIPT_SIZE,
            "MAX_STANDARD_P2WSH_STACK_ITEMS": MAX_STANDARD_P2WSH_STACK_ITEMS,
            "MAX_STANDARD_P2WSH_STACK_ITEM_SIZE": MAX_STANDARD_P2WSH_STACK_ITEM_SIZE,
        },
        "radix4_packing": rows,
        "candidates": {
            "fewer_shards_same_script": {
                "digest": "SHA-256",
                "shards": 8,
                "per_shard_inside_limits": true,
                "survives_item2_collision_bound": false,
                "note": "Birthday 2^128 classical / BHT ~2^85 quantum is below the sender-collision bar that keeps SHA-384."
            },
            "more_digits_per_shard": {
                "digits": 17,
                "inside_limits": false,
                "binding_limit": "201 counted opcodes"
            }
        }
    });
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../artifacts/seals");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("param_study.json"),
        serde_json::to_string_pretty(&report).unwrap(),
    )
    .unwrap();
}
