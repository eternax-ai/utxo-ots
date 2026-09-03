//! External detached-message verification (overlay, not consensus payment rules).

use bitcoin::consensus::Encodable;
use bitcoin::{Transaction, TxIn, TxOut};

use crate::error::Error;
use crate::message::{digest_digits, encode_message, parse_selectors};
use crate::parameters::{
    DIGITS_PER_SHARD, LOGICAL_DIGITS, PARAMETER_SET_ID, PublicKeyId, SHARD_COUNT,
};
use crate::script::ShardScript;
use crate::transaction::p2wsh_script_pubkey;

/// One canonical spend of a setup shard, possibly from a fragmented carrier.
#[derive(Debug, Clone)]
pub struct ShardSpend<'a> {
    pub shard_index: usize,
    pub tx: &'a Transaction,
    pub input_index: usize,
}

/// Verify a single aggregate publication transaction.
pub fn verify_detached(
    pkid: &PublicKeyId,
    message: &[u8],
    setup_outputs: &[TxOut],
    shard_scripts: &[ShardScript],
    publication: &Transaction,
) -> Result<[u8; LOGICAL_DIGITS], Error> {
    if publication.input.len() != SHARD_COUNT {
        return Err(Error::IncompleteShardSet);
    }
    let spends: Vec<ShardSpend<'_>> = (0..SHARD_COUNT)
        .map(|shard_index| ShardSpend {
            shard_index,
            tx: publication,
            input_index: shard_index,
        })
        .collect();
    verify_detached_spend_set(pkid, message, setup_outputs, shard_scripts, &spends)
}

/// Verify a set-of-spends signature (aggregate or fragmented).
///
/// Requires exactly one spend per shard. Carrier txids/outputs are ignored for
/// message binding.
pub fn verify_detached_spend_set(
    pkid: &PublicKeyId,
    message: &[u8],
    setup_outputs: &[TxOut],
    shard_scripts: &[ShardScript],
    spends: &[ShardSpend<'_>],
) -> Result<[u8; LOGICAL_DIGITS], Error> {
    if pkid.parameter_set_id != PARAMETER_SET_ID {
        return Err(Error::InvalidParameter("unknown parameter set"));
    }
    if pkid.shard_count as usize != SHARD_COUNT {
        return Err(Error::InvalidParameter("shard count"));
    }
    if setup_outputs.len() < SHARD_COUNT || shard_scripts.len() != SHARD_COUNT {
        return Err(Error::IncompleteShardSet);
    }
    if spends.len() != SHARD_COUNT {
        return Err(Error::IncompleteShardSet);
    }

    for i in 0..SHARD_COUNT {
        let expected = p2wsh_script_pubkey(&shard_scripts[i].script);
        if setup_outputs[i].script_pubkey != expected {
            return Err(Error::InvalidParameter("setup scriptPubKey mismatch"));
        }
    }

    let expected_digits = digest_digits(&encode_message(pkid, message));
    let mut observed = [0u8; LOGICAL_DIGITS];
    let mut seen = [false; SHARD_COUNT];

    let flags = bitcoinconsensus::VERIFY_P2SH
        | bitcoinconsensus::VERIFY_WITNESS
        | bitcoinconsensus::VERIFY_CHECKLOCKTIMEVERIFY
        | bitcoinconsensus::VERIFY_CHECKSEQUENCEVERIFY;

    for spend in spends {
        let shard = spend.shard_index;
        if shard >= SHARD_COUNT {
            return Err(Error::InvalidParameter("shard index out of range"));
        }
        if seen[shard] {
            return Err(Error::DuplicateShard);
        }
        seen[shard] = true;

        let txin = spend
            .tx
            .input
            .get(spend.input_index)
            .ok_or(Error::InvalidParameter("input index"))?;
        check_outpoint(pkid, shard, txin)?;

        let mut encoded = Vec::new();
        spend
            .tx
            .consensus_encode(&mut encoded)
            .map_err(|e| Error::Bitcoin(e.to_string()))?;

        let amount = setup_outputs[shard].value.to_sat();
        bitcoinconsensus::verify_with_flags(
            setup_outputs[shard].script_pubkey.as_bytes(),
            amount,
            &encoded,
            spend.input_index,
            flags,
        )
        .map_err(|e| Error::ScriptVerify(format!("shard {shard}: {e:?}")))?;

        parse_witness_digits(
            &txin.witness,
            &shard_scripts[shard],
            shard,
            &mut observed,
        )?;
    }

    if seen.iter().any(|s| !s) {
        return Err(Error::IncompleteShardSet);
    }
    if observed != expected_digits {
        return Err(Error::DigestMismatch);
    }
    Ok(observed)
}

/// Collect [`ShardSpend`]s from one or more publication transactions.
pub fn collect_spends_from_txs<'a>(
    pkid: &PublicKeyId,
    txs: &'a [Transaction],
) -> Result<Vec<ShardSpend<'a>>, Error> {
    let mut found: [Option<(usize, usize)>; SHARD_COUNT] = [None; SHARD_COUNT];
    // Store (tx_index, input_index) then rebuild references.
    for (ti, tx) in txs.iter().enumerate() {
        for (ii, txin) in tx.input.iter().enumerate() {
            if txin.previous_output.txid != pkid.setup_txid {
                continue;
            }
            let vout = txin.previous_output.vout;
            if vout < pkid.first_vout {
                continue;
            }
            let shard = (vout - pkid.first_vout) as usize;
            if shard >= SHARD_COUNT {
                continue;
            }
            if found[shard].is_some() {
                return Err(Error::DuplicateShard);
            }
            found[shard] = Some((ti, ii));
        }
    }
    let mut spends = Vec::with_capacity(SHARD_COUNT);
    for (shard, slot) in found.iter().enumerate() {
        let (ti, ii) = slot.ok_or(Error::IncompleteShardSet)?;
        spends.push(ShardSpend {
            shard_index: shard,
            tx: &txs[ti],
            input_index: ii,
        });
    }
    Ok(spends)
}

fn check_outpoint(pkid: &PublicKeyId, shard: usize, txin: &TxIn) -> Result<(), Error> {
    let expected_vout = pkid.first_vout + shard as u32;
    if txin.previous_output.txid != pkid.setup_txid || txin.previous_output.vout != expected_vout {
        return Err(Error::InvalidParameter("publication outpoint mismatch"));
    }
    Ok(())
}

fn parse_witness_digits(
    witness: &bitcoin::Witness,
    shard_script: &ShardScript,
    shard: usize,
    observed: &mut [u8; LOGICAL_DIGITS],
) -> Result<(), Error> {
    if witness.len() != DIGITS_PER_SHARD * 3 + 1 {
        return Err(Error::InvalidParameter("witness item count"));
    }
    let ws = witness
        .last()
        .ok_or(Error::InvalidParameter("empty witness"))?;
    if ws != shard_script.script.as_bytes() {
        return Err(Error::InvalidParameter("witness script mismatch"));
    }
    for local in 0..DIGITS_PER_SHARD {
        let base = local * 3;
        let preimage = witness
            .nth(base)
            .ok_or(Error::InvalidParameter("missing preimage"))?;
        let low = witness
            .nth(base + 1)
            .ok_or(Error::InvalidParameter("missing low selector"))?;
        let high = witness
            .nth(base + 2)
            .ok_or(Error::InvalidParameter("missing high selector"))?;
        if preimage.len() != 32 {
            return Err(Error::InvalidParameter("preimage length"));
        }
        let low_bit = match low {
            [] => 0,
            [1] => 1,
            _ => return Err(Error::InvalidParameter("noncanonical low selector")),
        };
        let high_bit = match high {
            [] => 0,
            [1] => 1,
            _ => return Err(Error::InvalidParameter("noncanonical high selector")),
        };
        let choice = parse_selectors(low_bit, high_bit)?;
        let digit_index = shard * DIGITS_PER_SHARD + (DIGITS_PER_SHARD - 1 - local);
        observed[digit_index] = choice;
    }
    Ok(())
}
