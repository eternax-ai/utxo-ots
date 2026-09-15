//! `seal-asset v0`: transition encoding, asset rules, and reason codes.
//!
//! Finding F-1: a bank is one-time, so a genesis close cannot both consume
//! `genesis_pkid` and leave a transferable holding on that same seal. Genesis
//! therefore accepts an optional trailing `first_holder` pkid. Omitted, the
//! holder is the signer (parked on a closed seal). Present, supply is assigned
//! to that open receiver bank — the RGB-shaped issue-then-transfer path.

use bitcoin::hashes::Hash;
use bitcoin::Txid;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::parameters::{NetworkId, PublicKeyId, PARAMETER_SET_ID, SHARD_COUNT};

/// Domain tag in `asset_id` and in the genesis payload.
pub const ASSET_DOMAIN: &[u8] = b"utxo-ots/seal-asset/v0";
pub const GENESIS_TAG: u8 = 0x01;
pub const TRANSFER_TAG: u8 = 0x02;

pub type AssetId = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    InvalidEncoding,
    UnknownTransitionType,
    GenesisDomainMismatch,
    SignerDoesNotHoldAsset,
    SupplyMismatch,
    ReceiverSealNotOpen,
    ReceiverAlreadyHoldsAsset,
    NetworkMismatch,
    IncompleteShardSet,
    DuplicateShard,
    SealClosedOverDifferentMessage,
    DigestMismatch,
    ScriptVerifyFailed,
    SetupNotFound,
    InvalidSetup,
    ConfirmationBelowPolicy,
    InconsistentPartialClosure,
    AssetIdMismatch,
    EmptyAllocation,
    ZeroAmount,
    TooManyReceivers,
}

impl std::fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ReasonCode {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition {
    Genesis {
        supply: u64,
        /// `None` means assign to the genesis signer (closed holding).
        first_holder: Option<PublicKeyId>,
    },
    Transfer {
        asset_id: AssetId,
        allocations: Vec<(PublicKeyId, u64)>,
    },
}

impl Transition {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Genesis {
                supply,
                first_holder,
            } => {
                let mut out = Vec::with_capacity(1 + ASSET_DOMAIN.len() + 8 + 64);
                out.push(GENESIS_TAG);
                out.extend_from_slice(ASSET_DOMAIN);
                out.extend_from_slice(&supply.to_be_bytes());
                if let Some(pk) = first_holder {
                    out.extend_from_slice(&pk.encode());
                }
                out
            }
            Self::Transfer {
                asset_id,
                allocations,
            } => {
                let mut out = Vec::new();
                out.push(TRANSFER_TAG);
                out.extend_from_slice(asset_id);
                out.push(allocations.len() as u8);
                for (pk, amount) in allocations {
                    out.extend_from_slice(&pk.encode());
                    out.extend_from_slice(&amount.to_be_bytes());
                }
                out
            }
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ReasonCode> {
        if bytes.is_empty() {
            return Err(ReasonCode::InvalidEncoding);
        }
        match bytes[0] {
            GENESIS_TAG => decode_genesis(&bytes[1..]),
            TRANSFER_TAG => decode_transfer(&bytes[1..]),
            _ => Err(ReasonCode::UnknownTransitionType),
        }
    }
}

fn decode_genesis(rest: &[u8]) -> Result<Transition, ReasonCode> {
    if rest.len() < ASSET_DOMAIN.len() + 8 {
        return Err(ReasonCode::InvalidEncoding);
    }
    let (dom, rest) = rest.split_at(ASSET_DOMAIN.len());
    if dom != ASSET_DOMAIN {
        return Err(ReasonCode::GenesisDomainMismatch);
    }
    let supply = u64::from_be_bytes(
        rest[..8]
            .try_into()
            .map_err(|_| ReasonCode::InvalidEncoding)?,
    );
    let rest = &rest[8..];
    let first_holder = if rest.is_empty() {
        None
    } else {
        let (pk, n) = decode_pkid(rest)?;
        if n != rest.len() {
            return Err(ReasonCode::InvalidEncoding);
        }
        Some(pk)
    };
    Ok(Transition::Genesis {
        supply,
        first_holder,
    })
}

fn decode_transfer(rest: &[u8]) -> Result<Transition, ReasonCode> {
    if rest.len() < 32 + 1 {
        return Err(ReasonCode::InvalidEncoding);
    }
    let mut asset_id = [0u8; 32];
    asset_id.copy_from_slice(&rest[..32]);
    let n = rest[32] as usize;
    if n == 0 {
        return Err(ReasonCode::EmptyAllocation);
    }
    if n > 255 {
        return Err(ReasonCode::TooManyReceivers);
    }
    let mut cursor = &rest[33..];
    let mut allocations = Vec::with_capacity(n);
    for _ in 0..n {
        let (pk, used) = decode_pkid(cursor)?;
        cursor = &cursor[used..];
        if cursor.len() < 8 {
            return Err(ReasonCode::InvalidEncoding);
        }
        let amount = u64::from_be_bytes(
            cursor[..8]
                .try_into()
                .map_err(|_| ReasonCode::InvalidEncoding)?,
        );
        cursor = &cursor[8..];
        if amount == 0 {
            return Err(ReasonCode::ZeroAmount);
        }
        allocations.push((pk, amount));
    }
    if !cursor.is_empty() {
        return Err(ReasonCode::InvalidEncoding);
    }
    Ok(Transition::Transfer {
        asset_id,
        allocations,
    })
}

/// `SHA256("utxo-ots/seal-asset/v0" || Encode(genesis_pkid))`.
pub fn asset_id(genesis_pkid: &PublicKeyId) -> AssetId {
    let mut hasher = Sha256::new();
    hasher.update(ASSET_DOMAIN);
    hasher.update(genesis_pkid.encode());
    hasher.finalize().into()
}

pub fn decode_pkid(data: &[u8]) -> Result<(PublicKeyId, usize), ReasonCode> {
    // network(1) + txid(32) + first_vout(4) + shard_count(4) + id_len(1) + id
    if data.len() < 1 + 32 + 4 + 4 + 1 {
        return Err(ReasonCode::InvalidEncoding);
    }
    let network = NetworkId::from_byte(data[0]).ok_or(ReasonCode::InvalidEncoding)?;
    let mut txid_bytes = [0u8; 32];
    txid_bytes.copy_from_slice(&data[1..33]);
    let setup_txid = Txid::from_byte_array(txid_bytes);
    let first_vout = u32::from_le_bytes(data[33..37].try_into().unwrap());
    let shard_count = u32::from_le_bytes(data[37..41].try_into().unwrap());
    let id_len = data[41] as usize;
    let need = 42 + id_len;
    if data.len() < need {
        return Err(ReasonCode::InvalidEncoding);
    }
    let parameter_set_id = std::str::from_utf8(&data[42..need])
        .map_err(|_| ReasonCode::InvalidEncoding)?
        .to_string();
    Ok((
        PublicKeyId {
            network,
            setup_txid,
            first_vout,
            shard_count,
            parameter_set_id,
        },
        need,
    ))
}

pub fn pkid_bytes(pkid: &PublicKeyId) -> Vec<u8> {
    pkid.encode()
}

pub fn pkids_equal(a: &PublicKeyId, b: &PublicKeyId) -> bool {
    a == b
}

/// Allocation named by a genesis or transfer. `signer` is used when genesis
/// omits `first_holder`.
pub fn genesis_holder<'a>(
    signer: &'a PublicKeyId,
    first_holder: &'a Option<PublicKeyId>,
) -> &'a PublicKeyId {
    first_holder.as_ref().unwrap_or(signer)
}

pub fn allocation_sum(allocations: &[(PublicKeyId, u64)]) -> Result<u64, ReasonCode> {
    allocations
        .iter()
        .try_fold(0u64, |acc, (_, amt)| acc.checked_add(*amt))
        .ok_or(ReasonCode::SupplyMismatch)
}

/// Rule 2 (conservation) and structural checks that do not need the chain.
pub fn check_transfer_rules(
    signer: &PublicKeyId,
    signer_balance: u64,
    asset: &AssetId,
    t: &Transition,
) -> Result<(), ReasonCode> {
    let Transition::Transfer {
        asset_id: tid,
        allocations,
    } = t
    else {
        return Err(ReasonCode::UnknownTransitionType);
    };
    if tid != asset {
        return Err(ReasonCode::AssetIdMismatch);
    }
    if allocations.is_empty() {
        return Err(ReasonCode::EmptyAllocation);
    }
    let sum = allocation_sum(allocations)?;
    if sum != signer_balance {
        return Err(ReasonCode::SupplyMismatch);
    }
    for (recv, amount) in allocations {
        if *amount == 0 {
            return Err(ReasonCode::ZeroAmount);
        }
        if recv.network != signer.network {
            return Err(ReasonCode::NetworkMismatch);
        }
        if recv == signer {
            return Err(ReasonCode::ReceiverSealNotOpen);
        }
    }
    Ok(())
}

pub fn check_genesis_rules(signer: &PublicKeyId, t: &Transition) -> Result<u64, ReasonCode> {
    let Transition::Genesis {
        supply,
        first_holder,
    } = t
    else {
        return Err(ReasonCode::UnknownTransitionType);
    };
    if *supply == 0 {
        return Err(ReasonCode::ZeroAmount);
    }
    if let Some(h) = first_holder {
        if h.network != signer.network {
            return Err(ReasonCode::NetworkMismatch);
        }
        if h.shard_count as usize != SHARD_COUNT {
            return Err(ReasonCode::InvalidSetup);
        }
        if h.parameter_set_id != PARAMETER_SET_ID {
            return Err(ReasonCode::InvalidSetup);
        }
    }
    Ok(*supply)
}

/// JSON consignment on disk. Carriers are consensus-hex.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsignmentJson {
    pub network: String,
    pub genesis: SignedJson,
    pub transitions: Vec<SignedJson>,
    pub carriers_hex: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedJson {
    pub pkid: PkidJson,
    pub message_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkidJson {
    pub network: String,
    pub setup_txid: String,
    pub first_vout: u32,
    pub shard_count: u32,
    pub parameter_set_id: String,
}

impl PkidJson {
    pub fn from_pkid(pkid: &PublicKeyId) -> Self {
        Self {
            network: network_name(pkid.network).to_string(),
            setup_txid: pkid.setup_txid.to_string(),
            first_vout: pkid.first_vout,
            shard_count: pkid.shard_count,
            parameter_set_id: pkid.parameter_set_id.clone(),
        }
    }

    pub fn to_pkid(&self) -> Result<PublicKeyId, ReasonCode> {
        Ok(PublicKeyId {
            network: parse_network_name(&self.network)?,
            setup_txid: parse_txid_display(&self.setup_txid)?,
            first_vout: self.first_vout,
            shard_count: self.shard_count,
            parameter_set_id: self.parameter_set_id.clone(),
        })
    }
}

pub fn network_name(n: NetworkId) -> &'static str {
    match n {
        NetworkId::Mainnet => "mainnet",
        NetworkId::Testnet => "testnet",
        NetworkId::Signet => "signet",
        NetworkId::Regtest => "regtest",
    }
}

pub fn parse_network_name(s: &str) -> Result<NetworkId, ReasonCode> {
    match s.to_ascii_lowercase().as_str() {
        "mainnet" | "bitcoin" => Ok(NetworkId::Mainnet),
        "testnet" => Ok(NetworkId::Testnet),
        "signet" => Ok(NetworkId::Signet),
        "regtest" => Ok(NetworkId::Regtest),
        _ => Err(ReasonCode::NetworkMismatch),
    }
}

fn parse_txid_display(s: &str) -> Result<Txid, ReasonCode> {
    let bytes = hex::decode(s.trim()).map_err(|_| ReasonCode::InvalidEncoding)?;
    if bytes.len() != 32 {
        return Err(ReasonCode::InvalidEncoding);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    arr.reverse();
    Ok(Txid::from_byte_array(arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parameters::SHARD_COUNT;

    fn pk(n: u8, net: NetworkId) -> PublicKeyId {
        PublicKeyId {
            network: net,
            setup_txid: Txid::from_byte_array([n; 32]),
            first_vout: 0,
            shard_count: SHARD_COUNT as u32,
            parameter_set_id: PARAMETER_SET_ID.to_string(),
        }
    }

    #[test]
    fn genesis_roundtrip_spec_encoding() {
        let t = Transition::Genesis {
            supply: 1_000,
            first_holder: None,
        };
        let b = t.encode();
        assert_eq!(b[0], GENESIS_TAG);
        assert_eq!(&b[1..1 + ASSET_DOMAIN.len()], ASSET_DOMAIN);
        assert_eq!(Transition::decode(&b).unwrap(), t);
    }

    #[test]
    fn genesis_roundtrip_with_holder() {
        let holder = pk(2, NetworkId::Regtest);
        let t = Transition::Genesis {
            supply: 42,
            first_holder: Some(holder.clone()),
        };
        assert_eq!(Transition::decode(&t.encode()).unwrap(), t);
    }

    #[test]
    fn transfer_roundtrip() {
        let t = Transition::Transfer {
            asset_id: [0xab; 32],
            allocations: vec![
                (pk(3, NetworkId::Regtest), 7),
                (pk(4, NetworkId::Regtest), 3),
            ],
        };
        assert_eq!(Transition::decode(&t.encode()).unwrap(), t);
    }

    #[test]
    fn genesis_and_transfer_type_tags_distinct() {
        let g = Transition::Genesis {
            supply: 1,
            first_holder: None,
        }
        .encode();
        let t = Transition::Transfer {
            asset_id: [0; 32],
            allocations: vec![(pk(1, NetworkId::Regtest), 1)],
        }
        .encode();
        assert_ne!(g[0], t[0]);
        assert!(matches!(
            Transition::decode(&[0x03]),
            Err(ReasonCode::UnknownTransitionType)
        ));
    }

    #[test]
    fn supply_mismatch_rejected() {
        let signer = pk(1, NetworkId::Regtest);
        let asset = asset_id(&signer);
        let t = Transition::Transfer {
            asset_id: asset,
            allocations: vec![(pk(2, NetworkId::Regtest), 50)],
        };
        assert_eq!(
            check_transfer_rules(&signer, 100, &asset, &t),
            Err(ReasonCode::SupplyMismatch)
        );
    }

    #[test]
    fn network_mismatch_rejected() {
        let signer = pk(1, NetworkId::Regtest);
        let asset = asset_id(&signer);
        let t = Transition::Transfer {
            asset_id: asset,
            allocations: vec![(pk(2, NetworkId::Testnet), 100)],
        };
        assert_eq!(
            check_transfer_rules(&signer, 100, &asset, &t),
            Err(ReasonCode::NetworkMismatch)
        );
    }

    #[test]
    fn replay_different_asset_id_rejected() {
        let signer = pk(1, NetworkId::Regtest);
        let asset = asset_id(&signer);
        let other = [0x11; 32];
        let t = Transition::Transfer {
            asset_id: other,
            allocations: vec![(pk(2, NetworkId::Regtest), 1)],
        };
        assert_eq!(
            check_transfer_rules(&signer, 1, &asset, &t),
            Err(ReasonCode::AssetIdMismatch)
        );
    }

    #[test]
    fn pkid_decode_matches_encode() {
        let p = pk(9, NetworkId::Signet);
        let enc = p.encode();
        let (got, n) = decode_pkid(&enc).unwrap();
        assert_eq!(n, enc.len());
        assert_eq!(got, p);
    }

    #[test]
    fn empty_and_zero_allocations_rejected() {
        assert!(matches!(
            Transition::decode(&[
                TRANSFER_TAG,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0
            ]),
            Err(ReasonCode::EmptyAllocation)
        ));
    }

    #[test]
    fn asset_id_binds_genesis_pkid() {
        assert_ne!(
            asset_id(&pk(1, NetworkId::Regtest)),
            asset_id(&pk(2, NetworkId::Regtest))
        );
        assert_ne!(
            asset_id(&pk(1, NetworkId::Regtest)),
            asset_id(&pk(1, NetworkId::Testnet))
        );
    }
}
