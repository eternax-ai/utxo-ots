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
    KEY_NONCE_LEN, NetworkId, PARAMETER_SET_ID, P2WSH_DUST_SATS, PublicKeyId, SHARD_COUNT,
};
use utxo_ots::script::shard_metrics;
use utxo_ots::transaction::{
    build_aggregate_publication, build_setup_outputs, build_setup_tx, tx_weight_report,
};
use utxo_ots::verifier::verify_detached;

#[derive(Parser, Debug)]
#[command(name = "utxo-ots", about = "P2WSH shard hash OTS (detached-message profile)")]
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
    println!("wrote {} ({} bytes hex)", path.display(), hex::encode(&bin).len());
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
                let outs =
                    build_setup_outputs(&bank, Amount::from_sat(shard_sats)).unwrap();
                match verify_detached(&pkid, message.as_bytes(), &outs, &bank.shard_scripts, &tx)
                {
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
    }
}
