//! Adversarial programme for `seal-asset v0` (RESEARCH_PLAN_V2.md).

use std::time::Instant;

use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use utxo_ots::keygen::SigningBank;
use utxo_ots::message::message_digits;
use utxo_ots::parameters::{
    NetworkId, PublicKeyId, P2WSH_DUST_SATS, PARAMETER_SET_ID, SHARD_COUNT,
};
use utxo_ots::resolver::{
    consignment_to_json, resolve, ConfirmationPolicy, Consignment, HoldingStatus, InMemoryChain,
    SignedMessage,
};
use utxo_ots::seal::{asset_id, ReasonCode, Transition};
use utxo_ots::transaction::{
    build_aggregate_publication, build_fragmented_publication, build_setup_tx, tx_weight_report,
};
use utxo_ots::{expose_for_sign, BankRecord, BankStore, Error};

const SUPPLY: u64 = 1_000_000;
const SHARD_SATS: u64 = 10_000;
const CONF: u32 = 6;

struct Party {
    bank: SigningBank,
    pkid: PublicKeyId,
    setup: Transaction,
}

fn gen_bank(label: u8) -> SigningBank {
    let mut nonce = [0u8; 16];
    nonce[0] = label;
    nonce[1] = 0x5a;
    SigningBank::generate(b"seal-asset-v0-test-master", nonce).unwrap()
}

fn fund(chain: &mut InMemoryChain, label: u8, conf: u32) -> Party {
    let bank = gen_bank(label);
    let funding = OutPoint {
        txid: Txid::from_byte_array([label; 32]),
        vout: 0,
    };
    let setup = build_setup_tx(
        funding,
        Amount::from_sat(SHARD_SATS * SHARD_COUNT as u64 + 5_000),
        &bank,
        Amount::from_sat(SHARD_SATS),
        None,
        Amount::from_sat(1_000),
    )
    .unwrap();
    let setup_txid = setup.compute_txid();
    chain.insert(setup.clone(), conf);
    let pkid = PublicKeyId {
        network: NetworkId::Regtest,
        setup_txid,
        first_vout: 0,
        shard_count: SHARD_COUNT as u32,
        parameter_set_id: PARAMETER_SET_ID.to_string(),
    };
    Party { bank, pkid, setup }
}

fn close_tx(party: &Party, message: &[u8]) -> Transaction {
    let digits = message_digits(&party.pkid, message);
    let openings = party.bank.openings_for_digits(&digits).unwrap();
    build_aggregate_publication(
        party.pkid.setup_txid,
        party.pkid.first_vout,
        Amount::from_sat(SHARD_SATS),
        &party.bank,
        &openings,
    )
    .unwrap()
}

fn close_fragments(party: &Party, message: &[u8]) -> Vec<Transaction> {
    let digits = message_digits(&party.pkid, message);
    let openings = party.bank.openings_for_digits(&digits).unwrap();
    build_fragmented_publication(
        party.pkid.setup_txid,
        party.pkid.first_vout,
        &party.bank,
        &openings,
        &(0..SHARD_COUNT).collect::<Vec<_>>(),
    )
    .unwrap()
}

fn genesis_msg(holder: &PublicKeyId) -> Vec<u8> {
    Transition::Genesis {
        supply: SUPPLY,
        first_holder: Some(holder.clone()),
    }
    .encode()
}

fn transfer_msg(asset: &[u8; 32], recv: &PublicKeyId, amount: u64) -> Vec<u8> {
    Transition::Transfer {
        asset_id: *asset,
        allocations: vec![(recv.clone(), amount)],
    }
    .encode()
}

fn mutate_outputs(tx: &Transaction) -> Transaction {
    Transaction {
        version: tx.version,
        lock_time: tx.lock_time,
        input: tx.input.clone(),
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new_op_return(b"stolen"),
        }],
    }
}

struct Issued {
    chain: InMemoryChain,
    g: Party,
    a: Party,
    b: Party,
    genesis_message: Vec<u8>,
    genesis_tx: Transaction,
    asset: [u8; 32],
}

fn issue() -> Issued {
    let mut chain = InMemoryChain::new();
    let g = fund(&mut chain, 1, CONF);
    let a = fund(&mut chain, 2, CONF);
    let b = fund(&mut chain, 3, CONF);
    let genesis_message = genesis_msg(&a.pkid);
    let genesis_tx = close_tx(&g, &genesis_message);
    chain.insert(genesis_tx.clone(), CONF);
    let asset = asset_id(&g.pkid);
    Issued {
        chain,
        g,
        a,
        b,
        genesis_message,
        genesis_tx,
        asset,
    }
}

fn consignment(
    issued: &Issued,
    transfers: Vec<(PublicKeyId, Vec<u8>)>,
    extra_carriers: Vec<Transaction>,
) -> Consignment {
    let mut carriers = vec![issued.genesis_tx.clone()];
    carriers.extend(extra_carriers);
    Consignment {
        network: NetworkId::Regtest,
        genesis: SignedMessage {
            pkid: issued.g.pkid.clone(),
            message_bytes: issued.genesis_message.clone(),
        },
        transitions: transfers
            .into_iter()
            .map(|(pkid, message_bytes)| SignedMessage {
                pkid,
                message_bytes,
            })
            .collect(),
        carriers,
    }
}

fn owner_is(res: &utxo_ots::Resolution, pkid: &PublicKeyId, amount: u64) -> bool {
    res.owners.len() == 1
        && res.owners[0].pkid == *pkid
        && res.owners[0].amount == amount
        && res.owners[0].status == HoldingStatus::Open
        && !res.pending
}

#[test]
fn honest_issue_then_transfer() {
    let mut issued = issue();
    let msg = transfer_msg(&issued.asset, &issued.b.pkid, SUPPLY);
    let tx = close_tx(&issued.a, &msg);
    issued.chain.insert(tx.clone(), CONF);
    let c = consignment(&issued, vec![(issued.a.pkid.clone(), msg)], vec![tx]);
    let res = resolve(&c, &issued.chain, ConfirmationPolicy::REFERENCE).unwrap();
    assert!(owner_is(&res, &issued.b.pkid, SUPPLY), "{res:?}");
}

#[test]
fn copied_witness_mutated_outputs_still_pays_b() {
    let mut issued = issue();
    let msg = transfer_msg(&issued.asset, &issued.b.pkid, SUPPLY);
    let honest = close_tx(&issued.a, &msg);
    let attack = mutate_outputs(&honest);
    issued.chain.insert(attack.clone(), CONF);
    let c = consignment(&issued, vec![(issued.a.pkid.clone(), msg)], vec![honest]);
    let res = resolve(&c, &issued.chain, ConfirmationPolicy::REFERENCE).unwrap();
    assert!(owner_is(&res, &issued.b.pkid, SUPPLY), "{res:?}");
}

#[test]
fn harvested_shard_closing_then_complete() {
    let mut issued = issue();
    let msg = transfer_msg(&issued.asset, &issued.b.pkid, SUPPLY);
    let fragments = close_fragments(&issued.a, &msg);
    issued.chain.insert(fragments[0].clone(), CONF);

    let c = consignment(
        &issued,
        vec![(issued.a.pkid.clone(), msg.clone())],
        fragments.clone(),
    );
    let pending = resolve(&c, &issued.chain, ConfirmationPolicy::REFERENCE).unwrap();
    assert!(pending.pending);
    assert_eq!(pending.owners.len(), 1);
    assert_eq!(pending.owners[0].pkid, issued.a.pkid);
    assert_eq!(pending.owners[0].status, HoldingStatus::Closing);

    for frag in fragments.iter().skip(1) {
        issued.chain.insert(frag.clone(), CONF);
    }
    let res = resolve(&c, &issued.chain, ConfirmationPolicy::REFERENCE).unwrap();
    assert!(owner_is(&res, &issued.b.pkid, SUPPLY), "{res:?}");
}

#[test]
fn transfer_without_preimages_fails_consensus() {
    let issued = issue();
    let msg = transfer_msg(&issued.asset, &issued.b.pkid, SUPPLY);
    let mut tx = close_tx(&issued.a, &msg);
    for input in &mut tx.input {
        input.witness = Witness::from_slice(&[vec![0u8; 32], vec![], vec![1], vec![0u8; 4]]);
    }
    let mut encoded = Vec::new();
    tx.consensus_encode(&mut encoded).unwrap();
    let outs = issued.a.setup.output.clone();
    let err = bitcoinconsensus::verify_with_flags(
        outs[0].script_pubkey.as_bytes(),
        outs[0].value.to_sat(),
        &encoded,
        0,
        bitcoinconsensus::VERIFY_P2SH | bitcoinconsensus::VERIFY_WITNESS,
    );
    assert!(err.is_err(), "garbage witness must fail consensus");
}

#[test]
fn conflicting_transfers_follow_canonical_chain() {
    let mut issued = issue();
    let c_party = fund(&mut issued.chain, 4, CONF);
    let msg_b = transfer_msg(&issued.asset, &issued.b.pkid, SUPPLY);
    let msg_c = transfer_msg(&issued.asset, &c_party.pkid, SUPPLY);

    let tx_b = close_tx(&issued.a, &msg_b);
    // Second sign from the same bank: preimages for a different digit vector.
    // The wallet must poison; we still construct the conflicting publication
    // to model an equivocating signer.
    let tx_c = close_tx(&issued.a, &msg_c);
    issued.chain.insert(tx_c.clone(), CONF);

    let dir = std::env::temp_dir().join(format!(
        "seal-poison-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut store = BankStore::create(&dir, BankRecord::new("a", "aa".repeat(16))).unwrap();
    store
        .set_funded(issued.a.pkid.setup_txid.to_string(), 0)
        .unwrap();
    expose_for_sign(&mut store, "first".into()).unwrap();
    store.poison("equivocation").unwrap();
    assert_eq!(store.record().status, utxo_ots::BankStatus::Poisoned);
    let _ = std::fs::remove_dir_all(&dir);

    let cons_c = consignment(&issued, vec![(issued.a.pkid.clone(), msg_c)], vec![tx_c]);
    let res = resolve(&cons_c, &issued.chain, ConfirmationPolicy::REFERENCE).unwrap();
    assert!(owner_is(&res, &c_party.pkid, SUPPLY), "{res:?}");

    let cons_b = consignment(&issued, vec![(issued.a.pkid.clone(), msg_b)], vec![tx_b]);
    assert_eq!(
        resolve(&cons_b, &issued.chain, ConfirmationPolicy::REFERENCE).unwrap_err(),
        ReasonCode::SealClosedOverDifferentMessage
    );
}

#[test]
fn receiver_seal_not_open() {
    let mut issued = issue();
    let spent = close_tx(&issued.b, b"unrelated-close");
    issued.chain.insert(spent, CONF);
    let msg = transfer_msg(&issued.asset, &issued.b.pkid, SUPPLY);
    let tx = close_tx(&issued.a, &msg);
    issued.chain.insert(tx.clone(), CONF);
    let c = consignment(&issued, vec![(issued.a.pkid.clone(), msg)], vec![tx]);
    assert_eq!(
        resolve(&c, &issued.chain, ConfirmationPolicy::REFERENCE).unwrap_err(),
        ReasonCode::ReceiverSealNotOpen
    );
}

#[test]
fn network_mismatch() {
    let mut issued = issue();
    let mut foreign = issued.b.pkid.clone();
    foreign.network = NetworkId::Testnet;
    let msg = transfer_msg(&issued.asset, &foreign, SUPPLY);
    let tx = close_tx(&issued.a, &msg);
    issued.chain.insert(tx.clone(), CONF);
    let c = consignment(&issued, vec![(issued.a.pkid.clone(), msg)], vec![tx]);
    assert_eq!(
        resolve(&c, &issued.chain, ConfirmationPolicy::REFERENCE).unwrap_err(),
        ReasonCode::NetworkMismatch
    );
}

#[test]
fn supply_mismatch() {
    let mut issued = issue();
    let msg = transfer_msg(&issued.asset, &issued.b.pkid, SUPPLY - 1);
    let tx = close_tx(&issued.a, &msg);
    issued.chain.insert(tx.clone(), CONF);
    let c = consignment(&issued, vec![(issued.a.pkid.clone(), msg)], vec![tx]);
    assert_eq!(
        resolve(&c, &issued.chain, ConfirmationPolicy::REFERENCE).unwrap_err(),
        ReasonCode::SupplyMismatch
    );
}

#[test]
fn random_bytes_close_is_closed_unknown() {
    let mut issued = issue();
    let garbage = vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02];
    let tx = close_tx(&issued.a, &garbage);
    issued.chain.insert(tx.clone(), CONF);
    let c = consignment(&issued, vec![], vec![]);
    let res = resolve(&c, &issued.chain, ConfirmationPolicy::REFERENCE).unwrap();
    assert_eq!(res.owners.len(), 1);
    assert_eq!(res.owners[0].pkid, issued.a.pkid);
    assert_eq!(res.owners[0].status, HoldingStatus::ClosedUnknown);
    assert_eq!(res.owners[0].amount, SUPPLY);
}

#[test]
fn consignment_omits_one_carrier() {
    let mut issued = issue();
    let msg = transfer_msg(&issued.asset, &issued.b.pkid, SUPPLY);
    let fragments = close_fragments(&issued.a, &msg);
    for frag in &fragments {
        issued.chain.insert(frag.clone(), CONF);
    }
    let mut partial = fragments.clone();
    partial.pop();
    let c = consignment(&issued, vec![(issued.a.pkid.clone(), msg)], partial);
    assert_eq!(
        resolve(&c, &issued.chain, ConfirmationPolicy::REFERENCE).unwrap_err(),
        ReasonCode::IncompleteShardSet
    );
}

#[test]
fn reordered_transitions_rejected() {
    let mut issued = issue();
    let c_party = fund(&mut issued.chain, 5, CONF);
    let msg_ab = transfer_msg(&issued.asset, &issued.b.pkid, SUPPLY);
    let tx_ab = close_tx(&issued.a, &msg_ab);
    issued.chain.insert(tx_ab.clone(), CONF);

    let msg_bc = transfer_msg(&issued.asset, &c_party.pkid, SUPPLY);
    let tx_bc = close_tx(&issued.b, &msg_bc);
    issued.chain.insert(tx_bc.clone(), CONF);

    let mut c = consignment(
        &issued,
        vec![
            (issued.b.pkid.clone(), msg_bc.clone()),
            (issued.a.pkid.clone(), msg_ab.clone()),
        ],
        vec![tx_ab, tx_bc],
    );
    assert_eq!(
        resolve(&c, &issued.chain, ConfirmationPolicy::REFERENCE).unwrap_err(),
        ReasonCode::SignerDoesNotHoldAsset
    );

    c.transitions.reverse();
    let res = resolve(&c, &issued.chain, ConfirmationPolicy::REFERENCE).unwrap();
    assert!(owner_is(&res, &c_party.pkid, SUPPLY), "{res:?}");
}

#[test]
fn replay_against_different_asset_id() {
    let mut issued = issue();
    let msg = transfer_msg(&issued.asset, &issued.b.pkid, SUPPLY);
    let tx = close_tx(&issued.a, &msg);
    issued.chain.insert(tx.clone(), CONF);

    let g2 = fund(&mut issued.chain, 6, CONF);
    let a2 = fund(&mut issued.chain, 7, CONF);
    let genesis2 = genesis_msg(&a2.pkid);
    let g2_tx = close_tx(&g2, &genesis2);
    issued.chain.insert(g2_tx.clone(), CONF);

    let c = Consignment {
        network: NetworkId::Regtest,
        genesis: SignedMessage {
            pkid: g2.pkid.clone(),
            message_bytes: genesis2,
        },
        transitions: vec![SignedMessage {
            pkid: issued.a.pkid.clone(),
            message_bytes: msg,
        }],
        carriers: vec![g2_tx, tx],
    };
    assert_eq!(
        resolve(&c, &issued.chain, ConfirmationPolicy::REFERENCE).unwrap_err(),
        ReasonCode::AssetIdMismatch
    );
}

#[test]
fn reorg_below_f_does_not_credit_wrong_owner() {
    let mut issued = issue();
    let msg = transfer_msg(&issued.asset, &issued.b.pkid, SUPPLY);
    let tx = close_tx(&issued.a, &msg);
    issued.chain.insert(tx.clone(), CONF);
    let c = consignment(
        &issued,
        vec![(issued.a.pkid.clone(), msg)],
        vec![tx.clone()],
    );
    let ok = resolve(&c, &issued.chain, ConfirmationPolicy::REFERENCE).unwrap();
    assert!(owner_is(&ok, &issued.b.pkid, SUPPLY));

    issued.chain.set_confirmations(tx.compute_txid(), 1);
    let pending = resolve(&c, &issued.chain, ConfirmationPolicy::REFERENCE).unwrap();
    assert!(pending.pending);
    assert_eq!(pending.owners.len(), 1);
    assert_eq!(pending.owners[0].pkid, issued.a.pkid);
    assert_ne!(pending.owners[0].pkid, issued.b.pkid);

    issued.chain.retract(tx.compute_txid());
    // Retract does not restore shard UTXOs (setup outputs were spent_by-only).
    // After retract, spends are gone so the transfer is missing from the chain
    // while the consignment still claims it.
    let err = resolve(&c, &issued.chain, ConfirmationPolicy::REFERENCE).unwrap_err();
    assert_eq!(err, ReasonCode::IncompleteShardSet);
}

#[test]
fn measurements_honest_path_and_hops() {
    let mut issued = issue();
    let setup_w = tx_weight_report(&issued.g.setup);
    let msg = transfer_msg(&issued.asset, &issued.b.pkid, SUPPLY);
    let agg = close_tx(&issued.a, &msg);
    let (agg_w, agg_v) = tx_weight_report(&agg);
    let frags = close_fragments(&issued.a, &msg);
    let frag_v: u64 = frags.iter().map(|t| tx_weight_report(t).1).sum();

    issued.chain.insert(agg.clone(), CONF);
    let c = consignment(&issued, vec![(issued.a.pkid.clone(), msg)], vec![agg]);
    let json = consignment_to_json(&c);
    let with_carriers = serde_json::to_vec(&json).unwrap().len();
    let mut no_carriers = json.clone();
    no_carriers.carriers_hex.clear();
    let without_carriers = serde_json::to_vec(&no_carriers).unwrap().len();

    let t0 = Instant::now();
    resolve(&c, &issued.chain, ConfirmationPolicy::REFERENCE).unwrap();
    let hop1_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let (hop8_ms, hop8_bytes) = hop_bench(8);
    let (hop32_ms, hop32_bytes) = hop_bench(32);

    let pub_v = agg_v;
    let rates = [1u64, 5, 20];
    let mut funding = Vec::new();
    for r in rates {
        let setup_fee = setup_w.1 * r;
        let pub_fee = pub_v * r;
        let per_shard = P2WSH_DUST_SATS.max((pub_fee + 11) / 12 + P2WSH_DUST_SATS);
        funding.push(serde_json::json!({
            "sat_per_vb": r,
            "setup_vb": setup_w.1,
            "setup_fee_sats": setup_fee,
            "publication_fee_sats_aggregate": pub_fee,
            "per_shard_funding_sats": per_shard,
        }));
    }

    let report = serde_json::json!({
        "setup_weight": setup_w.0,
        "setup_vb": setup_w.1,
        "aggregate_weight": agg_w,
        "aggregate_vb": agg_v,
        "fragmented_total_vb": frag_v,
        "consignment_bytes_1hop_with_carriers": with_carriers,
        "consignment_bytes_1hop_without_carriers": without_carriers,
        "resolver_ms_1hop": hop1_ms,
        "resolver_ms_8hop": hop8_ms,
        "resolver_ms_32hop": hop32_ms,
        "consignment_bytes_8hop_with_carriers": hop8_bytes,
        "consignment_bytes_32hop_with_carriers": hop32_bytes,
        "funding": funding,
        "light_client_per_hop": {
            "note": "witness-commitment path, not txid path",
            "carrier_witness_bytes_aggregate": witness_bytes(&c.carriers[c.carriers.len()-1]),
            "block_header_bytes": 80,
            "merkle_inclusion_bytes_depth8": 32 * 8,
            "witness_merkle_extra_bytes": 32,
        }
    });

    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../artifacts/seals");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("measurements.json"),
        serde_json::to_string_pretty(&report).unwrap(),
    )
    .unwrap();
    eprintln!("{}", serde_json::to_string_pretty(&report).unwrap());
}

fn witness_bytes(tx: &Transaction) -> usize {
    tx.input.iter().map(|i| i.witness.size()).sum()
}

fn hop_bench(hops: usize) -> (f64, usize) {
    let mut chain = InMemoryChain::new();
    let issuer = fund(&mut chain, 10, CONF);
    let mut holders = Vec::new();
    for i in 0..=hops {
        holders.push(fund(&mut chain, 20 + i as u8, CONF));
    }
    let genesis_message = genesis_msg(&holders[0].pkid);
    let genesis_tx = close_tx(&issuer, &genesis_message);
    chain.insert(genesis_tx.clone(), CONF);
    let asset = asset_id(&issuer.pkid);

    let mut carriers = vec![genesis_tx];
    let mut transitions = Vec::new();
    for i in 0..hops {
        let msg = transfer_msg(&asset, &holders[i + 1].pkid, SUPPLY);
        let tx = close_tx(&holders[i], &msg);
        chain.insert(tx.clone(), CONF);
        transitions.push(SignedMessage {
            pkid: holders[i].pkid.clone(),
            message_bytes: msg,
        });
        carriers.push(tx);
    }
    let c = Consignment {
        network: NetworkId::Regtest,
        genesis: SignedMessage {
            pkid: issuer.pkid.clone(),
            message_bytes: genesis_message,
        },
        transitions,
        carriers,
    };
    let bytes = serde_json::to_vec(&consignment_to_json(&c)).unwrap().len();
    let t0 = Instant::now();
    let res = resolve(&c, &chain, ConfirmationPolicy::REFERENCE).unwrap();
    assert!(owner_is(&res, &holders[hops].pkid, SUPPLY));
    (t0.elapsed().as_secs_f64() * 1000.0, bytes)
}

#[test]
fn garbage_input_is_not_error_enum_string() {
    let e = ReasonCode::SupplyMismatch;
    assert_eq!(e.to_string(), "SupplyMismatch");
}

#[test]
fn forged_empty_witness_is_script_failure_not_a_carrier() {
    let issued = issue();
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: issued.a.pkid.setup_txid,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new_op_return(b""),
        }],
    };
    let mut encoded = Vec::new();
    tx.consensus_encode(&mut encoded).unwrap();
    let err = bitcoinconsensus::verify_with_flags(
        issued.a.setup.output[0].script_pubkey.as_bytes(),
        issued.a.setup.output[0].value.to_sat(),
        &encoded,
        0,
        bitcoinconsensus::VERIFY_P2SH | bitcoinconsensus::VERIFY_WITNESS,
    );
    assert!(err.is_err());
    let _ = Error::ScriptVerify("n/a".into());
}
