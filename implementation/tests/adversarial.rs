//! Adversarial / fragmentation tests for the detached-message profile.

use bitcoin::Amount;
use bitcoin::hashes::Hash;
use bitcoin::{ScriptBuf, TxOut};
use spend_to_sign::keygen::SigningBank;
use spend_to_sign::message::message_digits;
use spend_to_sign::parameters::{
    NetworkId, PARAMETER_SET_ID, PublicKeyId, SHARD_COUNT,
};
use spend_to_sign::transaction::{
    build_aggregate_publication, build_fragmented_publication, build_publication_for_shards,
    build_setup_outputs, copy_shard_witness_mutated_outputs,
};
use spend_to_sign::verifier::{collect_spends_from_txs, verify_detached, verify_detached_spend_set};
use spend_to_sign::{BankRecord, BankStore, Error, expose_for_sign};

fn bank() -> SigningBank {
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(b"adv-test-nonce!!");
    SigningBank::generate(b"adversarial-master-seed", nonce).unwrap()
}

fn pkid(setup: bitcoin::Txid) -> PublicKeyId {
    PublicKeyId {
        network: NetworkId::Regtest,
        setup_txid: setup,
        first_vout: 0,
        shard_count: SHARD_COUNT as u32,
        parameter_set_id: PARAMETER_SET_ID.to_string(),
    }
}

#[test]
fn fragmented_publication_verifies() {
    let bank = bank();
    let setup = bitcoin::Txid::from_byte_array([0x33; 32]);
    let sats = Amount::from_sat(10_000);
    let outs = build_setup_outputs(&bank, sats).unwrap();
    let pk = pkid(setup);
    let msg = b"fragmented ok";
    let openings = bank
        .openings_for_digits(&message_digits(&pk, msg))
        .unwrap();
    let txs = build_fragmented_publication(setup, 0, &bank, &openings, &(0..12).collect::<Vec<_>>())
        .unwrap();
    assert_eq!(txs.len(), 12);
    let spends = collect_spends_from_txs(&pk, &txs).unwrap();
    verify_detached_spend_set(&pk, msg, &outs, &bank.shard_scripts, &spends).unwrap();
}

#[test]
fn harvested_shard_then_complete_remaining() {
    let bank = bank();
    let setup = bitcoin::Txid::from_byte_array([0x44; 32]);
    let sats = Amount::from_sat(10_000);
    let outs = build_setup_outputs(&bank, sats).unwrap();
    let pk = pkid(setup);
    let msg = b"harvest then finish";
    let openings = bank
        .openings_for_digits(&message_digits(&pk, msg))
        .unwrap();

    // Observer confirms shard 0 alone.
    let harvested = build_publication_for_shards(setup, 0, &bank, &openings, &[0]).unwrap();
    // Aggregate-only rule would be stuck; set-of-spends completes 1..11.
    let rest = build_fragmented_publication(setup, 0, &bank, &openings, &(1..12).collect::<Vec<_>>())
        .unwrap();
    let mut txs = vec![harvested];
    txs.extend(rest);
    let spends = collect_spends_from_txs(&pk, &txs).unwrap();
    verify_detached_spend_set(&pk, msg, &outs, &bank.shard_scripts, &spends).unwrap();

    // Aggregate alone is incomplete once we only have the harvest conceptually —
    // building aggregate still *constructs*, but verifying only the harvest fails.
    assert!(matches!(
        verify_detached(&pk, msg, &outs, &bank.shard_scripts, &txs[0]),
        Err(Error::IncompleteShardSet)
    ));
}

#[test]
fn copied_witness_mutated_outputs_same_digits() {
    let bank = bank();
    let setup = bitcoin::Txid::from_byte_array([0x55; 32]);
    let sats = Amount::from_sat(10_000);
    let outs = build_setup_outputs(&bank, sats).unwrap();
    let pk = pkid(setup);
    let msg = b"copy carrier";
    let openings = bank
        .openings_for_digits(&message_digits(&pk, msg))
        .unwrap();
    let agg = build_aggregate_publication(setup, 0, sats, &bank, &openings).unwrap();

    // Mutate outputs on a single-shard copy of input 3.
    let conflict = copy_shard_witness_mutated_outputs(
        &agg,
        3,
        vec![TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::new_op_return(b"stolen"),
        }],
    )
    .unwrap();

    // Consensus script check on the conflicting carrier alone for shard 3.
    let mut encoded = Vec::new();
    use bitcoin::consensus::Encodable;
    conflict.consensus_encode(&mut encoded).unwrap();
    bitcoinconsensus::verify_with_flags(
        outs[3].script_pubkey.as_bytes(),
        outs[3].value.to_sat(),
        &encoded,
        0,
        bitcoinconsensus::VERIFY_P2SH | bitcoinconsensus::VERIFY_WITNESS,
    )
    .expect("copied witness still opens under consensus");

    // Full signature still needs all shards; combine conflict(shard3) + rest from aggregate.
    // Build remaining shards 0,1,2,4..11 as fragments from same openings.
    let mut txs = Vec::new();
    for i in 0..12usize {
        if i == 3 {
            txs.push(conflict.clone());
        } else {
            txs.push(build_publication_for_shards(setup, 0, &bank, &openings, &[i]).unwrap());
        }
    }
    let spends = collect_spends_from_txs(&pk, &txs).unwrap();
    verify_detached_spend_set(&pk, msg, &outs, &bank.shard_scripts, &spends).unwrap();
    // Wrong message still fails.
    assert!(matches!(
        verify_detached_spend_set(&pk, b"other", &outs, &bank.shard_scripts, &spends),
        Err(Error::DigestMismatch)
    ));
}

#[test]
fn state_machine_blocks_second_sign() {
    let dir = std::env::temp_dir().join(format!(
        "sts-adv-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut store = BankStore::create(&dir, BankRecord::new("demo", "aa".repeat(16))).unwrap();
    store.set_funded("cc".repeat(32), 0).unwrap();
    expose_for_sign(&mut store, "eeff".into()).unwrap();
    assert!(store.begin_signing().is_err());
    let _ = std::fs::remove_dir_all(dir);
}
