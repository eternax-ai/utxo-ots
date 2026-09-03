//! Reference parameter set from RESEARCH_PLAN.md.

use serde::{Deserialize, Serialize};

/// Domain tag for secret derivation.
pub const SECRET_DOMAIN: &[u8] = b"spend-to-sign/secret/v1";
/// Domain tag for detached-message digests.
pub const MESSAGE_DOMAIN: &[u8] = b"spend-to-sign/message/v1";
/// Parameter-set identifier string embedded in pkid encodings.
pub const PARAMETER_SET_ID: &str = "sha384-w4-d16-s12-v1";

pub const DIGEST_BITS: usize = 384;
pub const RADIX: u8 = 4;
pub const LOG2_RADIX: usize = 2;
pub const LOGICAL_DIGITS: usize = DIGEST_BITS / LOG2_RADIX; // 192
pub const DIGITS_PER_SHARD: usize = 16;
pub const SHARD_COUNT: usize = LOGICAL_DIGITS / DIGITS_PER_SHARD; // 12
pub const ALTERNATIVES: usize = 4;
pub const PREIMAGE_LEN: usize = 32;
pub const COMMITMENT_LEN: usize = 32;
pub const KEY_NONCE_LEN: usize = 16;

/// P2WSH dust threshold (satoshis) under default Bitcoin Core policy.
pub const P2WSH_DUST_SATS: u64 = 330;

/// Policy / consensus limits used for self-checks.
pub const MAX_OPS_PER_SCRIPT: usize = 201;
pub const MAX_STANDARD_P2WSH_SCRIPT_SIZE: usize = 3600;
pub const MAX_STANDARD_P2WSH_STACK_ITEMS: usize = 100;
pub const MAX_STANDARD_P2WSH_STACK_ITEM_SIZE: usize = 80;
pub const MAX_STANDARD_TX_WEIGHT: usize = 400_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkId {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

impl NetworkId {
    pub fn as_byte(self) -> u8 {
        match self {
            Self::Mainnet => 0,
            Self::Testnet => 1,
            Self::Signet => 2,
            Self::Regtest => 3,
        }
    }

    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Mainnet),
            1 => Some(Self::Testnet),
            2 => Some(Self::Signet),
            3 => Some(Self::Regtest),
            _ => None,
        }
    }

    pub fn to_bitcoin(self) -> bitcoin::Network {
        match self {
            Self::Mainnet => bitcoin::Network::Bitcoin,
            Self::Testnet => bitcoin::Network::Testnet,
            Self::Signet => bitcoin::Network::Signet,
            Self::Regtest => bitcoin::Network::Regtest,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParameterSet {
    pub digest_bits: usize,
    pub radix: u8,
    pub digits_per_shard: usize,
    pub shard_count: usize,
}

pub const REF: ParameterSet = ParameterSet {
    digest_bits: DIGEST_BITS,
    radix: RADIX,
    digits_per_shard: DIGITS_PER_SHARD,
    shard_count: SHARD_COUNT,
};

/// Compact public-key identifier.
///
/// Authoritative key material is the setup P2WSH outputs themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyId {
    pub network: NetworkId,
    pub setup_txid: bitcoin::Txid,
    pub first_vout: u32,
    pub shard_count: u32,
    pub parameter_set_id: String,
}

impl PublicKeyId {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 32 + 4 + 4 + 1 + self.parameter_set_id.len());
        out.push(self.network.as_byte());
        out.extend_from_slice(self.setup_txid.as_ref());
        out.extend_from_slice(&self.first_vout.to_le_bytes());
        out.extend_from_slice(&self.shard_count.to_le_bytes());
        let id = self.parameter_set_id.as_bytes();
        assert!(id.len() <= 255);
        out.push(id.len() as u8);
        out.extend_from_slice(id);
        out
    }
}
