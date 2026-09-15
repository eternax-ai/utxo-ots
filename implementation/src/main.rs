//! CLI: generate a bank, build setup outputs, sign a message into an aggregate tx.

use std::path::PathBuf;

use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::hashes::Hash;
use bitcoin::{Address, Amount, OutPoint, Transaction, Txid};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use utxo_ots::keygen::SigningBank;
use utxo_ots::message::message_digits;
use utxo_ots::parameters::{
    NetworkId, PublicKeyId, KEY_NONCE_LEN, P2WSH_DUST_SATS, PARAMETER_SET_ID, SHARD_COUNT,
};
use utxo_ots::resolver::{chain_from_txs, consignment_from_json, resolve, ConfirmationPolicy};
use utxo_ots::script::shard_metrics;
use utxo_ots::seal::{asset_id, ConsignmentJson, PkidJson, Transition};
use utxo_ots::transaction::{
    build_aggregate_publication, build_setup_outputs, build_setup_tx, tx_weight_report,
};
use utxo_ots::verifier::verify_detached;

#[derive(Parser, Debug)]
#[command(
    name = "utxo-ots",
    about = "P2WSH shard hash OTS (detached-message profile)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Generate a bank and print shard script metrics + P2WSH scriptPubKeys.
    Keygen {
        /// Hex master seed (keep secret; never commit).
        #[arg(long)]
        master: String,
        /// Hex 16-byte key nonce (or omit to derive from master||label).
        #[arg(long)]
        key_nonce: Option<String>,
        #[arg(long, default_value = "regtest")]
        network: String,
        /// Satoshis per shard output.
        #[arg(long, default_value_t = 10_000)]
        shard_sats: u64,
    },
    /// Build an unsigned setup tx funding 12 shard outputs from one outpoint.
    Setup {
        #[arg(long)]
        master: String,
        #[arg(long)]
        key_nonce: Option<String>,
        /// Funding outpoint txid (hex).
        #[arg(long)]
        funding_txid: String,
        #[arg(long, default_value_t = 0)]
        funding_vout: u32,
        #[arg(long)]
        funding_sats: u64,
        #[arg(long, default_value_t = 10_000)]
        shard_sats: u64,
        #[arg(long, default_value_t = 500)]
        fee_sats: u64,
        #[arg(long, default_value = "setup.tx")]
        out: PathBuf,
    },
    /// Build a fully-witnessed aggregate publication tx for a message.
    Sign {
        #[arg(long)]
        master: String,
        #[arg(long)]
        key_nonce: Option<String>,
        #[arg(long)]
        setup_txid: String,
        #[arg(long, default_value_t = 0)]
        first_vout: u32,
        #[arg(long, default_value_t = 10_000)]
        shard_sats: u64,
        #[arg(long, default_value = "regtest")]
        network: String,
        /// Message bytes as UTF-8 string.
        #[arg(long)]
        message: String,
        #[arg(long, default_value = "sign.tx")]
        out: PathBuf,
        /// Also run local consensus+digest verify.
        #[arg(long, default_value_t = true)]
        verify: bool,
    },
    /// Verify a publication tx against setup outputs reconstructed from the bank.
    Verify {
        #[arg(long)]
        master: String,
        #[arg(long)]
        key_nonce: Option<String>,
        #[arg(long)]
        setup_txid: String,
        #[arg(long, default_value_t = 0)]
        first_vout: u32,
        #[arg(long, default_value_t = 10_000)]
        shard_sats: u64,
        #[arg(long, default_value = "regtest")]
        network: String,
        #[arg(long)]
        message: String,
        #[arg(long)]
        tx: PathBuf,
    },
    /// Close a genesis seal, assigning supply to an open holder bank.
    SealGenesis {
        #[arg(long)]
        master: String,
        #[arg(long)]
        key_nonce: Option<String>,
        #[arg(long)]
        setup_txid: String,
        #[arg(long, default_value_t = 0)]
        first_vout: u32,
        #[arg(long, default_value_t = 10_000)]
        shard_sats: u64,
        #[arg(long, default_value = "regtest")]
        network: String,
        #[arg(long)]
        supply: u64,
        #[arg(long)]
        holder_setup_txid: String,
        #[arg(long, default_value_t = 0)]
        holder_first_vout: u32,
        #[arg(long, default_value = "consignment.json")]
        consignment: PathBuf,
        #[arg(long, default_value = "genesis.tx")]
        out: PathBuf,
        #[arg(long, default_value_t = true)]
        verify: bool,
    },
    /// Close a holding seal over a transfer to one receiver bank.
    SealTransfer {
        #[arg(long)]
        master: String,
        #[arg(long)]
        key_nonce: Option<String>,
        #[arg(long)]
        setup_txid: String,
        #[arg(long, default_value_t = 0)]
        first_vout: u32,
        #[arg(long, default_value_t = 10_000)]
        shard_sats: u64,
        #[arg(long, default_value = "regtest")]
        network: String,
        #[arg(long)]
        consignment_in: PathBuf,
        #[arg(long)]
        receiver_setup_txid: String,
        #[arg(long, default_value_t = 0)]
        receiver_first_vout: u32,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value = "consignment.json")]
        consignment_out: PathBuf,
        #[arg(long, default_value = "transfer.tx")]
        out: PathBuf,
        #[arg(long, default_value_t = true)]
        verify: bool,
    },
    /// Resolve a consignment against setup txs and confirmed carriers.
    SealResolve {
        #[arg(long)]
        consignment: PathBuf,
        /// Hex-encoded setup transactions (repeatable).
        #[arg(long = "setup-tx")]
        setup_tx: Vec<PathBuf>,
        /// Hex-encoded confirmed spends; defaults to consignment carriers.
        #[arg(long = "confirmed-tx")]
        confirmed_tx: Vec<PathBuf>,
        #[arg(long, default_value_t = 1)]
        min_confirmations: u32,
    },
    /// Copy a publication's witnesses onto a carrier paying OP_RETURN "stolen".
    SealCopyAttack {
        #[arg(long)]
        tx: PathBuf,
        #[arg(long, default_value = "attack.tx")]
        out: PathBuf,
    },
}

fn parse_network(s: &str) -> NetworkId {
    match s.to_ascii_lowercase().as_str() {
        "mainnet" | "bitcoin" => NetworkId::Mainnet,
        "testnet" => NetworkId::Testnet,
        "signet" => NetworkId::Signet,
        _ => NetworkId::Regtest,
    }
}

fn parse_master(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str.trim()).expect("master hex")
}

fn parse_nonce(master: &[u8], explicit: &Option<String>) -> [u8; KEY_NONCE_LEN] {
    if let Some(h) = explicit {
        let v = hex::decode(h.trim()).expect("key_nonce hex");
        assert_eq!(v.len(), KEY_NONCE_LEN, "key_nonce must be 16 bytes");
        let mut n = [0u8; KEY_NONCE_LEN];
        n.copy_from_slice(&v);
        return n;
    }
    // Deterministic demo nonce — not for production entropy.
    let mut hasher = Sha256::new();
    hasher.update(b"utxo-ots/demo-nonce/v1");
    hasher.update(master);
    let d = hasher.finalize();
    let mut n = [0u8; KEY_NONCE_LEN];
    n.copy_from_slice(&d[..KEY_NONCE_LEN]);
    n
}

fn parse_txid(s: &str) -> Txid {
    let bytes = hex::decode(s.trim()).expect("txid hex");
    assert_eq!(bytes.len(), 32);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    // Bitcoin txids are displayed in reverse byte order; accept display hex.
    Txid::from_byte_array({
        let mut rev = arr;
        rev.reverse();
        rev
    })
}

fn write_tx(path: &PathBuf, tx: &Transaction) {
    let mut bin = Vec::new();
    tx.consensus_encode(&mut bin).unwrap();
    std::fs::write(path, hex::encode(&bin)).unwrap();
    let (w, v) = tx_weight_report(tx);
    println!(
        "wrote {} ({} bytes hex)",
        path.display(),
        hex::encode(&bin).len()
    );
    println!("txid={}", tx.compute_txid());
    println!("weight={w} vbytes={v}");
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Keygen {
            master,
            key_nonce,
            network,
            shard_sats,
        } => {
            let master = parse_master(&master);
            let nonce = parse_nonce(&master, &key_nonce);
            let bank = SigningBank::generate(&master, nonce).unwrap();
            let per = shard_sats.max(P2WSH_DUST_SATS);
            let outs = build_setup_outputs(&bank, Amount::from_sat(per)).unwrap();
            let net = parse_network(&network);
            println!("network={}", network);
            println!("key_nonce={}", hex::encode(nonce));
            println!("parameter_set={PARAMETER_SET_ID}");
            println!(
                "fund_total_sats={} ({} shards × {} sats) + miner_fee",
                per * SHARD_COUNT as u64,
                SHARD_COUNT,
                per
            );
            println!("note: fund via ONE setup tx with consecutive vouts 0..11 (see `setup`)");
            for (i, shard) in bank.shard_scripts.iter().enumerate() {
                let m = shard_metrics(shard);
                let addr = Address::from_script(&outs[i].script_pubkey, net.to_bitcoin())
                    .expect("p2wsh address");
                println!(
                    "shard[{i}] size={} ops={} items={} address={addr}",
                    m.script_size, m.counted_opcodes, m.witness_stack_items
                );
            }
        }
        Cmd::Setup {
            master,
            key_nonce,
            funding_txid,
            funding_vout,
            funding_sats,
            shard_sats,
            fee_sats,
            out,
        } => {
            let master = parse_master(&master);
            let nonce = parse_nonce(&master, &key_nonce);
            let bank = SigningBank::generate(&master, nonce).unwrap();
            let tx = build_setup_tx(
                OutPoint {
                    txid: parse_txid(&funding_txid),
                    vout: funding_vout,
                },
                Amount::from_sat(funding_sats),
                &bank,
                Amount::from_sat(shard_sats),
                None,
                Amount::from_sat(fee_sats),
            )
            .unwrap();
            println!("unsigned setup tx — sign funding input externally");
            write_tx(&out, &tx);
        }
        Cmd::Sign {
            master,
            key_nonce,
            setup_txid,
            first_vout,
            shard_sats,
            network,
            message,
            out,
            verify,
        } => {
            let master = parse_master(&master);
            let nonce = parse_nonce(&master, &key_nonce);
            let bank = SigningBank::generate(&master, nonce).unwrap();
            let setup_txid = parse_txid(&setup_txid);
            let net = parse_network(&network);
            // Provisional pkid uses the provided setup txid (after setup confirms).
            let pkid = PublicKeyId {
                network: net,
                setup_txid,
                first_vout,
                shard_count: SHARD_COUNT as u32,
                parameter_set_id: PARAMETER_SET_ID.to_string(),
            };
            let digits = message_digits(&pkid, message.as_bytes());
            let openings = bank.openings_for_digits(&digits).unwrap();
            let tx = build_aggregate_publication(
                setup_txid,
                first_vout,
                Amount::from_sat(shard_sats),
                &bank,
                &openings,
            )
            .unwrap();
            write_tx(&out, &tx);

            if verify {
                let outs = build_setup_outputs(&bank, Amount::from_sat(shard_sats)).unwrap();
                match verify_detached(&pkid, message.as_bytes(), &outs, &bank.shard_scripts, &tx) {
                    Ok(_) => println!("verify: OK (consensus openings + digest)"),
                    Err(e) => println!("verify: FAIL {e}"),
                }
            }
        }
        Cmd::Verify {
            master,
            key_nonce,
            setup_txid,
            first_vout,
            shard_sats,
            network,
            message,
            tx,
        } => {
            let master = parse_master(&master);
            let nonce = parse_nonce(&master, &key_nonce);
            let bank = SigningBank::generate(&master, nonce).unwrap();
            let setup_txid = parse_txid(&setup_txid);
            let pkid = PublicKeyId {
                network: parse_network(&network),
                setup_txid,
                first_vout,
                shard_count: SHARD_COUNT as u32,
                parameter_set_id: PARAMETER_SET_ID.to_string(),
            };
            let hex_str = std::fs::read_to_string(&tx).unwrap();
            let raw = hex::decode(hex_str.trim()).unwrap();
            let publication = Transaction::consensus_decode(&mut raw.as_slice()).unwrap();
            let outs = build_setup_outputs(&bank, Amount::from_sat(shard_sats)).unwrap();
            match verify_detached(
                &pkid,
                message.as_bytes(),
                &outs,
                &bank.shard_scripts,
                &publication,
            ) {
                Ok(d) => {
                    println!("OK digits={}", d.len());
                }
                Err(e) => {
                    eprintln!("FAIL {e}");
                    std::process::exit(1);
                }
            }
        }
        Cmd::SealGenesis {
            master,
            key_nonce,
            setup_txid,
            first_vout,
            shard_sats,
            network,
            supply,
            holder_setup_txid,
            holder_first_vout,
            consignment,
            out,
            verify,
        } => {
            let net = parse_network(&network);
            let master = parse_master(&master);
            let nonce = parse_nonce(&master, &key_nonce);
            let bank = SigningBank::generate(&master, nonce).unwrap();
            let pkid = make_pkid(net, parse_txid(&setup_txid), first_vout);
            let holder = make_pkid(net, parse_txid(&holder_setup_txid), holder_first_vout);
            let message = Transition::Genesis {
                supply,
                first_holder: Some(holder),
            }
            .encode();
            let tx = sign_publication(&bank, &pkid, &message, shard_sats);
            write_tx(&out, &tx);
            if verify {
                verify_local(&bank, &pkid, &message, shard_sats, &tx);
            }
            let file = ConsignmentJson {
                network: network.to_ascii_lowercase(),
                genesis: utxo_ots::seal::SignedJson {
                    pkid: PkidJson::from_pkid(&pkid),
                    message_hex: hex::encode(&message),
                },
                transitions: vec![],
                carriers_hex: vec![read_hex_file(&out)],
            };
            write_json(&consignment, &file);
            println!("asset_id={}", hex::encode(asset_id(&pkid)));
            println!("consignment={}", consignment.display());
        }
        Cmd::SealTransfer {
            master,
            key_nonce,
            setup_txid,
            first_vout,
            shard_sats,
            network,
            consignment_in,
            receiver_setup_txid,
            receiver_first_vout,
            amount,
            consignment_out,
            out,
            verify,
        } => {
            let net = parse_network(&network);
            let master = parse_master(&master);
            let nonce = parse_nonce(&master, &key_nonce);
            let bank = SigningBank::generate(&master, nonce).unwrap();
            let pkid = make_pkid(net, parse_txid(&setup_txid), first_vout);
            let receiver = make_pkid(net, parse_txid(&receiver_setup_txid), receiver_first_vout);
            let mut file: ConsignmentJson = read_json(&consignment_in);
            let genesis_pk = file.genesis.pkid.to_pkid().expect("genesis pkid");
            let aid = asset_id(&genesis_pk);
            let message = Transition::Transfer {
                asset_id: aid,
                allocations: vec![(receiver, amount)],
            }
            .encode();
            let tx = sign_publication(&bank, &pkid, &message, shard_sats);
            write_tx(&out, &tx);
            if verify {
                verify_local(&bank, &pkid, &message, shard_sats, &tx);
            }
            file.transitions.push(utxo_ots::seal::SignedJson {
                pkid: PkidJson::from_pkid(&pkid),
                message_hex: hex::encode(&message),
            });
            file.carriers_hex.push(read_hex_file(&out));
            write_json(&consignment_out, &file);
            println!("asset_id={}", hex::encode(aid));
            println!("consignment={}", consignment_out.display());
        }
        Cmd::SealResolve {
            consignment,
            setup_tx,
            confirmed_tx,
            min_confirmations,
        } => {
            let file: ConsignmentJson = read_json(&consignment);
            let c = consignment_from_json(&file).unwrap_or_else(|e| {
                eprintln!("consignment: {e}");
                std::process::exit(1);
            });
            let setups: Vec<Transaction> = setup_tx.iter().map(|p| read_tx(p)).collect();
            let confirmed: Vec<Transaction> = if confirmed_tx.is_empty() {
                c.carriers.clone()
            } else {
                confirmed_tx.iter().map(|p| read_tx(p)).collect()
            };
            let chain = chain_from_txs(setups, confirmed, min_confirmations);
            match resolve(&c, &chain, ConfirmationPolicy { min_confirmations }) {
                Ok(res) => {
                    println!("asset_id={}", hex::encode(res.asset_id));
                    println!("supply={}", res.supply);
                    println!("pending={}", res.pending);
                    for o in &res.owners {
                        println!(
                            "owner setup_txid={} vout={} amount={} status={:?}",
                            o.pkid.setup_txid, o.pkid.first_vout, o.amount, o.status
                        );
                    }
                    if res.owners.is_empty() {
                        println!("owners=(none)");
                    }
                }
                Err(e) => {
                    eprintln!("FAIL {e}");
                    std::process::exit(1);
                }
            }
        }
        Cmd::SealCopyAttack { tx, out } => {
            let original = read_tx(&tx);
            let attack = Transaction {
                version: original.version,
                lock_time: original.lock_time,
                input: original.input.clone(),
                output: vec![bitcoin::TxOut {
                    value: Amount::from_sat(0),
                    script_pubkey: bitcoin::ScriptBuf::new_op_return(b"stolen"),
                }],
            };
            write_tx(&out, &attack);
        }
    }
}

fn make_pkid(network: NetworkId, setup_txid: Txid, first_vout: u32) -> PublicKeyId {
    PublicKeyId {
        network,
        setup_txid,
        first_vout,
        shard_count: SHARD_COUNT as u32,
        parameter_set_id: PARAMETER_SET_ID.to_string(),
    }
}

fn sign_publication(
    bank: &SigningBank,
    pkid: &PublicKeyId,
    message: &[u8],
    shard_sats: u64,
) -> Transaction {
    let digits = message_digits(pkid, message);
    let openings = bank.openings_for_digits(&digits).unwrap();
    build_aggregate_publication(
        pkid.setup_txid,
        pkid.first_vout,
        Amount::from_sat(shard_sats),
        bank,
        &openings,
    )
    .unwrap()
}

fn verify_local(
    bank: &SigningBank,
    pkid: &PublicKeyId,
    message: &[u8],
    shard_sats: u64,
    tx: &Transaction,
) {
    let outs = build_setup_outputs(bank, Amount::from_sat(shard_sats)).unwrap();
    match verify_detached(pkid, message, &outs, &bank.shard_scripts, tx) {
        Ok(_) => println!("verify: OK (consensus openings + digest)"),
        Err(e) => println!("verify: FAIL {e}"),
    }
}

fn read_tx(path: &PathBuf) -> Transaction {
    let raw = hex::decode(read_hex_file(path)).expect("tx hex");
    Transaction::consensus_decode(&mut raw.as_slice()).expect("tx decode")
}

fn read_hex_file(path: &PathBuf) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .trim()
        .to_string()
}

fn read_json<T: serde::de::DeserializeOwned>(path: &PathBuf) -> T {
    let text = std::fs::read_to_string(path).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn write_json<T: serde::Serialize>(path: &PathBuf, v: &T) {
    std::fs::write(path, serde_json::to_string_pretty(v).unwrap()).unwrap();
    println!("wrote {}", path.display());
}
