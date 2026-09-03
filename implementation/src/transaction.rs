//! Setup outputs and aggregate / fragmented publication transactions.

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, WScriptHash,
    opcodes::all::OP_RETURN,
};

use crate::error::Error;
use crate::keygen::{DigitOpening, SigningBank};
use crate::parameters::{DIGITS_PER_SHARD, P2WSH_DUST_SATS, SHARD_COUNT};
use crate::script::ShardScript;

/// P2WSH scriptPubKey for a shard witness script.
pub fn p2wsh_script_pubkey(witness_script: &ScriptBuf) -> ScriptBuf {
    let hash = WScriptHash::hash(witness_script.as_bytes());
    ScriptBuf::new_p2wsh(&hash)
}

/// Build 12 equal-valued P2WSH outputs for a setup transaction.
pub fn build_setup_outputs(bank: &SigningBank, value_per_shard: Amount) -> Result<Vec<TxOut>, Error> {
    if value_per_shard.to_sat() < P2WSH_DUST_SATS {
        return Err(Error::InvalidParameter("shard value below P2WSH dust"));
    }
    if bank.shard_scripts.len() != SHARD_COUNT {
        return Err(Error::InvalidParameter("bank shard count"));
    }
    Ok(bank
        .shard_scripts
        .iter()
        .map(|s| TxOut {
            value: value_per_shard,
            script_pubkey: p2wsh_script_pubkey(&s.script),
        })
        .collect())
}

/// Build an unsigned setup transaction skeleton: one funding input + 12 shard outputs.
///
/// The funding input must be signed externally (ordinary ECDSA/Schnorr). Shard
/// outputs are pure hashlocks.
pub fn build_setup_tx(
    funding: OutPoint,
    funding_value: Amount,
    bank: &SigningBank,
    value_per_shard: Amount,
    change_script: Option<ScriptBuf>,
    fee: Amount,
) -> Result<Transaction, Error> {
    let outputs = build_setup_outputs(bank, value_per_shard)?;
    let shards_total = value_per_shard
        .checked_mul(SHARD_COUNT as u64)
        .ok_or(Error::InsufficientValue)?;
    let needed = shards_total
        .checked_add(fee)
        .ok_or(Error::InsufficientValue)?;
    if funding_value < needed {
        return Err(Error::InsufficientValue);
    }
    let mut tx_outs = outputs;
    let change = funding_value - needed;
    if let Some(script) = change_script {
        if change.to_sat() >= P2WSH_DUST_SATS {
            tx_outs.push(TxOut {
                value: change,
                script_pubkey: script,
            });
        }
    }
    Ok(Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: funding,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: tx_outs,
    })
}

fn bool_witness(bit: u8) -> Vec<u8> {
    if bit == 0 {
        Vec::new()
    } else {
        vec![0x01]
    }
}

/// Build the P2WSH witness for one shard from its 16 digit openings.
///
/// Stack order: digits 15…0 each as `<preimage> <lowBit> <highBit>`, then the
/// witness script.
pub fn shard_witness(shard: &ShardScript, openings: &[DigitOpening]) -> Result<Witness, Error> {
    if openings.len() != DIGITS_PER_SHARD {
        return Err(Error::InvalidParameter("expected 16 openings per shard"));
    }
    let mut stack: Vec<Vec<u8>> = Vec::with_capacity(DIGITS_PER_SHARD * 3 + 1);
    for opening in openings.iter().rev() {
        stack.push(opening.preimage.to_vec());
        stack.push(bool_witness(opening.low_bit));
        stack.push(bool_witness(opening.high_bit));
    }
    stack.push(shard.script.to_bytes());
    Ok(Witness::from_slice(&stack))
}

/// Aggregate publication: spend all 12 shards, burn value as fees, one OP_RETURN.
pub fn build_aggregate_publication(
    setup_txid: Txid,
    first_vout: u32,
    _shard_value: Amount,
    bank: &SigningBank,
    openings: &[DigitOpening],
) -> Result<Transaction, Error> {
    build_publication_for_shards(
        setup_txid,
        first_vout,
        bank,
        openings,
        &(0..SHARD_COUNT).collect::<Vec<_>>(),
    )
}

/// Publication spending an arbitrary non-empty subset of shards.
pub fn build_publication_for_shards(
    setup_txid: Txid,
    first_vout: u32,
    bank: &SigningBank,
    openings: &[DigitOpening],
    shard_indices: &[usize],
) -> Result<Transaction, Error> {
    if openings.len() != crate::parameters::LOGICAL_DIGITS {
        return Err(Error::InvalidParameter("expected 192 openings"));
    }
    if bank.shard_scripts.len() != SHARD_COUNT {
        return Err(Error::IncompleteShardSet);
    }
    if shard_indices.is_empty() {
        return Err(Error::InvalidParameter("empty shard set"));
    }
    let mut seen = [false; SHARD_COUNT];
    for &i in shard_indices {
        if i >= SHARD_COUNT {
            return Err(Error::InvalidParameter("shard index out of range"));
        }
        if seen[i] {
            return Err(Error::DuplicateShard);
        }
        seen[i] = true;
    }

    let mut inputs = Vec::with_capacity(shard_indices.len());
    for &i in shard_indices {
        let mut txin = TxIn {
            previous_output: OutPoint {
                txid: setup_txid,
                vout: first_vout + i as u32,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };
        let start = i * DIGITS_PER_SHARD;
        let end = start + DIGITS_PER_SHARD;
        txin.witness = shard_witness(&bank.shard_scripts[i], &openings[start..end])?;
        inputs.push(txin);
    }

    let opreturn = ScriptBuf::builder()
        .push_opcode(OP_RETURN)
        .into_script();

    Ok(Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs,
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: opreturn,
        }],
    })
}

/// One transaction per remaining shard (maximal fragmentation).
pub fn build_fragmented_publication(
    setup_txid: Txid,
    first_vout: u32,
    bank: &SigningBank,
    openings: &[DigitOpening],
    remaining_shards: &[usize],
) -> Result<Vec<Transaction>, Error> {
    remaining_shards
        .iter()
        .map(|&i| build_publication_for_shards(setup_txid, first_vout, bank, openings, &[i]))
        .collect()
}

/// Copy one input's witness onto a conflicting carrier with mutated outputs.
///
/// Consensus may accept this; detached message digits are unchanged.
pub fn copy_shard_witness_mutated_outputs(
    original: &Transaction,
    input_index: usize,
    new_outputs: Vec<TxOut>,
) -> Result<Transaction, Error> {
    if input_index >= original.input.len() {
        return Err(Error::InvalidParameter("input index"));
    }
    Ok(Transaction {
        version: original.version,
        lock_time: original.lock_time,
        input: vec![original.input[input_index].clone()],
        output: new_outputs,
    })
}

/// Weight and vbytes of a transaction.
pub fn tx_weight_report(tx: &Transaction) -> (u64, u64) {
    let w = tx.weight().to_wu();
    let v = tx.weight().to_vbytes_ceil();
    (w, v)
}
