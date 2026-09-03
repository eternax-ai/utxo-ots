//! End-to-end: build aggregate publication and verify with libbitcoinconsensus.

use bitcoin::Amount;
use bitcoin::hashes::Hash;
use utxo_ots::keygen::SigningBank;
use utxo_ots::message::message_digits;
use utxo_ots::parameters::{
    NetworkId, PARAMETER_SET_ID, PublicKeyId, SHARD_COUNT,
};
use utxo_ots::script::shard_metrics;
use utxo_ots::transaction::{
    build_aggregate_publication, build_setup_outputs, tx_weight_report,
};
use utxo_ots::verifier::verify_detached;

#[test]
fn aggregate_sign_and_verify() {
    let master = b"test-master-seed-do-not-use";
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(b"nonce-16-bytes!!");
    let bank = SigningBank::generate(master, nonce).unwrap();

    let m = shard_metrics(&bank.shard_scripts[0]);
    assert_eq!(m.script_size, 2305);
    assert_eq!(m.counted_opcodes, 192);

    let setup_txid = bitcoin::Txid::from_byte_array([0x11; 32]);
    let first_vout = 0u32;
    let shard_sats = Amount::from_sat(10_000);
    let outs = build_setup_outputs(&bank, shard_sats).unwrap();
    assert_eq!(outs.len(), SHARD_COUNT);

    let pkid = PublicKeyId {
        network: NetworkId::Regtest,
        setup_txid,
        first_vout,
        shard_count: SHARD_COUNT as u32,
        parameter_set_id: PARAMETER_SET_ID.to_string(),
    };
    let msg = b"utxo-ots phase1 demo";
    let digits = message_digits(&pkid, msg);
    let openings = bank.openings_for_digits(&digits).unwrap();
    let tx = build_aggregate_publication(setup_txid, first_vout, shard_sats, &bank, &openings)
        .unwrap();

    let (w, v) = tx_weight_report(&tx);
    eprintln!("aggregate weight={w} vbytes={v}");
    assert!(w < 400_000);
    // Phase-0 estimate was ~36670; allow modest serializer variance.
    assert!((30_000..45_000).contains(&w), "unexpected weight {w}");

    verify_detached(&pkid, msg, &outs, &bank.shard_scripts, &tx).expect("verify");
}

#[test]
fn wrong_message_fails() {
    let master = b"test-master-seed-do-not-use";
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(b"nonce-16-bytes!!");
    let bank = SigningBank::generate(master, nonce).unwrap();
    let setup_txid = bitcoin::Txid::from_byte_array([0x22; 32]);
    let shard_sats = Amount::from_sat(10_000);
    let outs = build_setup_outputs(&bank, shard_sats).unwrap();
    let pkid = PublicKeyId {
        network: NetworkId::Regtest,
        setup_txid,
        first_vout: 0,
        shard_count: SHARD_COUNT as u32,
        parameter_set_id: PARAMETER_SET_ID.to_string(),
    };
    let openings = bank
        .openings_for_digits(&message_digits(&pkid, b"alpha"))
        .unwrap();
    let tx = build_aggregate_publication(setup_txid, 0, shard_sats, &bank, &openings).unwrap();
    let err = verify_detached(&pkid, b"beta", &outs, &bank.shard_scripts, &tx).unwrap_err();
    assert!(matches!(err, utxo_ots::Error::DigestMismatch));
}
