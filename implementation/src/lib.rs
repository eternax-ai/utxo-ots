//! UTXO-OTS: ledger-finalized hash OTS via standard P2WSH shards.
//!
//! Bitcoin consensus verifies hash-preimage openings. An external verifier
//! checks that opened branches encode the message digest. This is not a
//! consensus payment-authorization scheme.

pub mod error;
pub mod keygen;
pub mod message;
pub mod parameters;
pub mod resolver;
pub mod script;
pub mod seal;
pub mod state;
pub mod transaction;
pub mod verifier;

pub use error::Error;
pub use keygen::{setup_scripts, SigningBank};
pub use message::{digest_digits, encode_message};
pub use parameters::{NetworkId, ParameterSet, PublicKeyId, REF};
pub use resolver::{
    chain_from_txs, consignment_from_json, consignment_to_json, resolve, ChainView,
    ConfirmationPolicy, Consignment, HoldingStatus, InMemoryChain, OwnerEntry, Resolution,
    SignedMessage,
};
pub use script::{shard_metrics, ShardScript};
pub use seal::{asset_id, ReasonCode, Transition};
pub use state::{expose_for_sign, BankRecord, BankStatus, BankStore};
pub use transaction::{
    build_aggregate_publication, build_fragmented_publication, build_publication_for_shards,
    build_setup_outputs, copy_shard_witness_mutated_outputs,
};
pub use verifier::{
    collect_spends_from_txs, verify_detached, verify_detached_spend_set, ShardSpend,
};
