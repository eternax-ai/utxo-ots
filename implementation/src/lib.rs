//! UTXO-OTS: ledger-finalized hash OTS via standard P2WSH shards.
//!
//! Bitcoin consensus verifies hash-preimage openings. An external verifier
//! checks that opened branches encode the message digest. This is not a
//! consensus payment-authorization scheme.

pub mod error;
pub mod keygen;
pub mod message;
pub mod parameters;
pub mod script;
pub mod state;
pub mod transaction;
pub mod verifier;

pub use error::Error;
pub use keygen::{SigningBank, setup_scripts};
pub use message::{digest_digits, encode_message};
pub use parameters::{NetworkId, ParameterSet, PublicKeyId, REF};
pub use script::{ShardScript, shard_metrics};
pub use state::{BankRecord, BankStatus, BankStore, expose_for_sign};
pub use transaction::{
    build_aggregate_publication, build_fragmented_publication, build_publication_for_shards,
    build_setup_outputs, copy_shard_witness_mutated_outputs,
};
pub use verifier::{
    ShardSpend, collect_spends_from_txs, verify_detached, verify_detached_spend_set,
};
