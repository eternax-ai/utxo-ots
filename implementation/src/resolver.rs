//! Consignment resolver: walk genesis and transfers over a chain view.
//!
//! Carrier outputs are ignored. Canonical spends of each seal's 12 shards are
//! the closure; the message is the opened branch vector. Finding F-2: witness
//! digit parsing is duplicated here because `verifier.rs` is frozen for Phase A.

use std::collections::{HashMap, HashSet};

use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::{OutPoint, ScriptBuf, Transaction, TxOut, Txid, Witness};

use crate::error::Error;
use crate::message::{digest_digits, encode_message, parse_selectors};
use crate::parameters::{
    PublicKeyId, DIGITS_PER_SHARD, LOGICAL_DIGITS, PARAMETER_SET_ID, SHARD_COUNT,
};
use crate::script::ShardScript;
use crate::seal::{
    allocation_sum, asset_id, check_genesis_rules, check_transfer_rules, genesis_holder,
    network_name, parse_network_name, pkid_bytes, AssetId, ConsignmentJson, PkidJson, ReasonCode,
    SignedJson, Transition,
};
use crate::transaction::p2wsh_script_pubkey;
use crate::verifier::{collect_spends_from_txs, verify_detached_spend_set, ShardSpend};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmationPolicy {
    pub min_confirmations: u32,
}

impl ConfirmationPolicy {
    pub const REFERENCE: Self = Self {
        min_confirmations: 6,
    };
    pub const REGTEST: Self = Self {
        min_confirmations: 1,
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldingStatus {
    Open,
    Closing,
    Closed,
    ClosedUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerEntry {
    pub pkid: PublicKeyId,
    pub amount: u64,
    pub status: HoldingStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    pub asset_id: AssetId,
    pub supply: u64,
    pub genesis_pkid: PublicKeyId,
    pub owners: Vec<OwnerEntry>,
    /// A claimed close is on the canonical chain but not `F`-final.
    pub pending: bool,
}

impl Resolution {
    pub fn owner_amounts(&self) -> Vec<(Vec<u8>, u64)> {
        self.owners
            .iter()
            .filter(|o| o.status != HoldingStatus::ClosedUnknown)
            .map(|o| (pkid_bytes(&o.pkid), o.amount))
            .collect()
    }

    pub fn unique_open_owner(&self) -> Option<&PublicKeyId> {
        let open: Vec<_> = self
            .owners
            .iter()
            .filter(|o| o.status == HoldingStatus::Open && o.amount > 0)
            .collect();
        match open.len() {
            1 => Some(&open[0].pkid),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SignedMessage {
    pub pkid: PublicKeyId,
    pub message_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Consignment {
    pub network: crate::parameters::NetworkId,
    pub genesis: SignedMessage,
    pub transitions: Vec<SignedMessage>,
    pub carriers: Vec<Transaction>,
}

pub trait ChainView {
    fn tx(&self, txid: Txid) -> Option<&Transaction>;
    fn confirmations(&self, txid: Txid) -> u32;
    /// Canonical spend of `outpoint`, if any: (txid, input index).
    fn spend(&self, outpoint: OutPoint) -> Option<(Txid, usize)>;
    fn utxo(&self, outpoint: OutPoint) -> Option<&TxOut>;
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryChain {
    txs: HashMap<Txid, Transaction>,
    confirmations: HashMap<Txid, u32>,
    spent_by: HashMap<OutPoint, (Txid, usize)>,
    utxos: HashMap<OutPoint, TxOut>,
}

impl InMemoryChain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, tx: Transaction, confirmations: u32) {
        let txid = tx.compute_txid();
        for (vin, input) in tx.input.iter().enumerate() {
            self.spent_by.insert(input.previous_output, (txid, vin));
            self.utxos.remove(&input.previous_output);
        }
        for (vout, output) in tx.output.iter().enumerate() {
            self.utxos.insert(
                OutPoint {
                    txid,
                    vout: vout as u32,
                },
                output.clone(),
            );
        }
        self.txs.insert(txid, tx);
        self.confirmations.insert(txid, confirmations);
    }

    pub fn set_confirmations(&mut self, txid: Txid, n: u32) {
        self.confirmations.insert(txid, n);
    }

    /// Drop a tx from the canonical view (reorg), restoring its inputs as UTXOs
    /// if we still have the parent tx.
    pub fn retract(&mut self, txid: Txid) {
        let Some(tx) = self.txs.remove(&txid) else {
            return;
        };
        self.confirmations.remove(&txid);
        for (vout, _) in tx.output.iter().enumerate() {
            self.utxos.remove(&OutPoint {
                txid,
                vout: vout as u32,
            });
        }
        for input in &tx.input {
            if self.spent_by.get(&input.previous_output).map(|(t, _)| *t) == Some(txid) {
                self.spent_by.remove(&input.previous_output);
            }
        }
    }
}

impl ChainView for InMemoryChain {
    fn tx(&self, txid: Txid) -> Option<&Transaction> {
        self.txs.get(&txid)
    }
    fn confirmations(&self, txid: Txid) -> u32 {
        self.confirmations.get(&txid).copied().unwrap_or(0)
    }
    fn spend(&self, outpoint: OutPoint) -> Option<(Txid, usize)> {
        self.spent_by.get(&outpoint).copied()
    }
    fn utxo(&self, outpoint: OutPoint) -> Option<&TxOut> {
        self.utxos.get(&outpoint)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SealClose {
    Open,
    Closing,
    Closed,
}

struct ObservedClose<'a> {
    state: SealClose,
    spends: Vec<ShardSpend<'a>>,
    scripts: Vec<ShardScript>,
    setup_outputs: Vec<TxOut>,
}

fn shard_outpoint(pkid: &PublicKeyId, shard: usize) -> OutPoint {
    OutPoint {
        txid: pkid.setup_txid,
        vout: pkid.first_vout + shard as u32,
    }
}

fn load_setup_outputs<C: ChainView>(
    chain: &C,
    pkid: &PublicKeyId,
) -> Result<Vec<TxOut>, ReasonCode> {
    if pkid.parameter_set_id != PARAMETER_SET_ID {
        return Err(ReasonCode::InvalidSetup);
    }
    if pkid.shard_count as usize != SHARD_COUNT {
        return Err(ReasonCode::InvalidSetup);
    }
    let setup = chain.tx(pkid.setup_txid).ok_or(ReasonCode::SetupNotFound)?;
    let start = pkid.first_vout as usize;
    let end = start + SHARD_COUNT;
    if setup.output.len() < end {
        return Err(ReasonCode::InvalidSetup);
    }
    let outs = setup.output[start..end].to_vec();
    for o in &outs {
        if !o.script_pubkey.is_p2wsh() {
            return Err(ReasonCode::InvalidSetup);
        }
    }
    Ok(outs)
}

fn collect_observed<'a, C: ChainView>(
    chain: &'a C,
    pkid: &PublicKeyId,
    policy: ConfirmationPolicy,
) -> Result<ObservedClose<'a>, ReasonCode> {
    let setup_outputs = load_setup_outputs(chain, pkid)?;
    let mut spends = Vec::new();
    let mut scripts: Vec<Option<ShardScript>> = (0..SHARD_COUNT).map(|_| None).collect();
    let mut spent = 0usize;
    let mut final_spent = 0usize;

    for shard in 0..SHARD_COUNT {
        let Some((txid, vin)) = chain.spend(shard_outpoint(pkid, shard)) else {
            continue;
        };
        spent += 1;
        let tx = chain.tx(txid).ok_or(ReasonCode::SetupNotFound)?;
        let conf = chain.confirmations(txid);
        if conf >= policy.min_confirmations {
            final_spent += 1;
        }
        let wit = &tx
            .input
            .get(vin)
            .ok_or(ReasonCode::InvalidEncoding)?
            .witness;
        let script = script_from_witness(wit)?;
        if p2wsh_script_pubkey(&script.script) != setup_outputs[shard].script_pubkey {
            return Err(ReasonCode::InvalidSetup);
        }
        scripts[shard] = Some(script);
        spends.push(ShardSpend {
            shard_index: shard,
            tx,
            input_index: vin,
        });
    }

    let state = if spent == 0 {
        SealClose::Open
    } else if final_spent == SHARD_COUNT {
        SealClose::Closed
    } else {
        SealClose::Closing
    };

    let scripts = scripts.into_iter().flatten().collect();
    Ok(ObservedClose {
        state,
        spends,
        scripts,
        setup_outputs,
    })
}

fn script_from_witness(witness: &Witness) -> Result<ShardScript, ReasonCode> {
    let ws = witness.last().ok_or(ReasonCode::InvalidEncoding)?;
    Ok(ShardScript {
        script: ScriptBuf::from(ws.to_vec()),
        script_size: ws.len(),
        counted_opcodes: 0,
        witness_stack_items: witness.len(),
    })
}

fn verify_closed(
    pkid: &PublicKeyId,
    message: &[u8],
    obs: &ObservedClose<'_>,
) -> Result<(), ReasonCode> {
    if obs.spends.len() != SHARD_COUNT || obs.scripts.len() != SHARD_COUNT {
        return Err(ReasonCode::IncompleteShardSet);
    }
    // `verify_detached_spend_set` expects scripts in shard-index order 0..12.
    let mut ordered_scripts = Vec::with_capacity(SHARD_COUNT);
    let mut by_shard: Vec<Option<ShardScript>> = (0..SHARD_COUNT).map(|_| None).collect();
    for (spend, script) in obs.spends.iter().zip(obs.scripts.iter()) {
        by_shard[spend.shard_index] = Some(script.clone());
    }
    for s in by_shard {
        ordered_scripts.push(s.ok_or(ReasonCode::IncompleteShardSet)?);
    }
    verify_detached_spend_set(
        pkid,
        message,
        &obs.setup_outputs,
        &ordered_scripts,
        &obs.spends,
    )
    .map(|_| ())
    .map_err(map_verify_err)
}

fn map_verify_err(e: Error) -> ReasonCode {
    match e {
        Error::IncompleteShardSet => ReasonCode::IncompleteShardSet,
        Error::DuplicateShard => ReasonCode::DuplicateShard,
        Error::DigestMismatch => ReasonCode::DigestMismatch,
        Error::ScriptVerify(_) => ReasonCode::ScriptVerifyFailed,
        _ => ReasonCode::InvalidEncoding,
    }
}

/// Consensus-check each spend and parse digits. Frozen-verifier duplicate (F-2).
fn observe_digits(
    pkid: &PublicKeyId,
    setup_outputs: &[TxOut],
    spends: &[ShardSpend<'_>],
) -> Result<([u8; LOGICAL_DIGITS], [bool; SHARD_COUNT]), ReasonCode> {
    let flags = bitcoinconsensus::VERIFY_P2SH
        | bitcoinconsensus::VERIFY_WITNESS
        | bitcoinconsensus::VERIFY_CHECKLOCKTIMEVERIFY
        | bitcoinconsensus::VERIFY_CHECKSEQUENCEVERIFY;
    let mut observed = [0u8; LOGICAL_DIGITS];
    let mut seen = [false; SHARD_COUNT];
    for spend in spends {
        let shard = spend.shard_index;
        if shard >= SHARD_COUNT {
            return Err(ReasonCode::InvalidEncoding);
        }
        if seen[shard] {
            return Err(ReasonCode::DuplicateShard);
        }
        seen[shard] = true;
        let txin = spend
            .tx
            .input
            .get(spend.input_index)
            .ok_or(ReasonCode::InvalidEncoding)?;
        let expected_vout = pkid.first_vout + shard as u32;
        if txin.previous_output.txid != pkid.setup_txid
            || txin.previous_output.vout != expected_vout
        {
            return Err(ReasonCode::InvalidEncoding);
        }
        let mut encoded = Vec::new();
        spend
            .tx
            .consensus_encode(&mut encoded)
            .map_err(|_| ReasonCode::InvalidEncoding)?;
        bitcoinconsensus::verify_with_flags(
            setup_outputs[shard].script_pubkey.as_bytes(),
            setup_outputs[shard].value.to_sat(),
            &encoded,
            spend.input_index,
            flags,
        )
        .map_err(|_| ReasonCode::ScriptVerifyFailed)?;

        parse_witness_digits(&txin.witness, shard, &mut observed)?;
    }
    Ok((observed, seen))
}

fn parse_witness_digits(
    witness: &Witness,
    shard: usize,
    observed: &mut [u8; LOGICAL_DIGITS],
) -> Result<(), ReasonCode> {
    if witness.len() != DIGITS_PER_SHARD * 3 + 1 {
        return Err(ReasonCode::InvalidEncoding);
    }
    for local in 0..DIGITS_PER_SHARD {
        let base = local * 3;
        let preimage = witness.nth(base).ok_or(ReasonCode::InvalidEncoding)?;
        let low = witness.nth(base + 1).ok_or(ReasonCode::InvalidEncoding)?;
        let high = witness.nth(base + 2).ok_or(ReasonCode::InvalidEncoding)?;
        if preimage.len() != 32 {
            return Err(ReasonCode::InvalidEncoding);
        }
        let low_bit = match low {
            [] => 0,
            [1] => 1,
            _ => return Err(ReasonCode::InvalidEncoding),
        };
        let high_bit = match high {
            [] => 0,
            [1] => 1,
            _ => return Err(ReasonCode::InvalidEncoding),
        };
        let choice = parse_selectors(low_bit, high_bit).map_err(|_| ReasonCode::InvalidEncoding)?;
        let digit_index = shard * DIGITS_PER_SHARD + (DIGITS_PER_SHARD - 1 - local);
        observed[digit_index] = choice;
    }
    Ok(())
}

fn digits_match_message(
    pkid: &PublicKeyId,
    message: &[u8],
    observed: &[u8; LOGICAL_DIGITS],
    seen: &[bool; SHARD_COUNT],
) -> bool {
    let expected = digest_digits(&encode_message(pkid, message));
    for shard in 0..SHARD_COUNT {
        if !seen[shard] {
            continue;
        }
        let start = shard * DIGITS_PER_SHARD;
        let end = start + DIGITS_PER_SHARD;
        if observed[start..end] != expected[start..end] {
            return false;
        }
    }
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloseCheck {
    Final,
    Pending,
}

fn require_consignment_complete(
    pkid: &PublicKeyId,
    carriers: &[Transaction],
) -> Result<(), ReasonCode> {
    collect_spends_from_txs(pkid, carriers)
        .map(|_| ())
        .map_err(map_verify_err)
}

fn check_claimed_close(
    pkid: &PublicKeyId,
    message: &[u8],
    carriers: &[Transaction],
    obs: &ObservedClose<'_>,
) -> Result<CloseCheck, ReasonCode> {
    require_consignment_complete(pkid, carriers)?;
    match obs.state {
        SealClose::Open => Err(ReasonCode::IncompleteShardSet),
        SealClose::Closing => {
            let (digits, seen) = observe_digits(pkid, &obs.setup_outputs, &obs.spends)?;
            if !digits_match_message(pkid, message, &digits, &seen) {
                return Err(ReasonCode::InconsistentPartialClosure);
            }
            Ok(CloseCheck::Pending)
        }
        SealClose::Closed => match verify_closed(pkid, message, obs) {
            Ok(()) => Ok(CloseCheck::Final),
            Err(ReasonCode::DigestMismatch) => Err(ReasonCode::SealClosedOverDifferentMessage),
            Err(e) => Err(e),
        },
    }
}

struct Holdings {
    map: HashMap<Vec<u8>, (PublicKeyId, u64)>,
}

impl Holdings {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
    fn insert(&mut self, pkid: PublicKeyId, amount: u64) -> Result<(), ReasonCode> {
        let k = pkid_bytes(&pkid);
        if self.map.contains_key(&k) {
            return Err(ReasonCode::ReceiverAlreadyHoldsAsset);
        }
        self.map.insert(k, (pkid, amount));
        Ok(())
    }
    fn take(&mut self, pkid: &PublicKeyId) -> Result<u64, ReasonCode> {
        self.map
            .remove(&pkid_bytes(pkid))
            .map(|(_, a)| a)
            .ok_or(ReasonCode::SignerDoesNotHoldAsset)
    }
    fn contains(&self, pkid: &PublicKeyId) -> bool {
        self.map.contains_key(&pkid_bytes(pkid))
    }
}

fn check_receiver(
    chain: &impl ChainView,
    signer: &PublicKeyId,
    recv: &PublicKeyId,
    holdings: &Holdings,
    later_signers: &HashSet<Vec<u8>>,
    policy: ConfirmationPolicy,
) -> Result<(), ReasonCode> {
    if recv.network != signer.network {
        return Err(ReasonCode::NetworkMismatch);
    }
    if holdings.contains(recv) {
        return Err(ReasonCode::ReceiverAlreadyHoldsAsset);
    }
    let _ = load_setup_outputs(chain, recv)?;
    let obs = collect_observed(chain, recv, policy)?;
    match obs.state {
        SealClose::Open => Ok(()),
        SealClose::Closing | SealClose::Closed => {
            if later_signers.contains(&pkid_bytes(recv)) {
                Ok(())
            } else {
                Err(ReasonCode::ReceiverSealNotOpen)
            }
        }
    }
}

/// Resolve a consignment against a chain view and confirmation policy `F`.
pub fn resolve<C: ChainView>(
    consignment: &Consignment,
    chain: &C,
    policy: ConfirmationPolicy,
) -> Result<Resolution, ReasonCode> {
    if consignment.genesis.pkid.network != consignment.network {
        return Err(ReasonCode::NetworkMismatch);
    }

    let genesis_pkid = consignment.genesis.pkid.clone();
    let genesis_obs = collect_observed(chain, &genesis_pkid, policy)?;
    let genesis_check = check_claimed_close(
        &genesis_pkid,
        &consignment.genesis.message_bytes,
        &consignment.carriers,
        &genesis_obs,
    )?;

    let gtx = Transition::decode(&consignment.genesis.message_bytes)?;
    let supply = check_genesis_rules(&genesis_pkid, &gtx)?;
    let Transition::Genesis { first_holder, .. } = &gtx else {
        return Err(ReasonCode::UnknownTransitionType);
    };
    let holder = genesis_holder(&genesis_pkid, first_holder).clone();
    let aid = asset_id(&genesis_pkid);

    if genesis_check == CloseCheck::Pending {
        return Ok(Resolution {
            asset_id: aid,
            supply,
            genesis_pkid,
            owners: vec![],
            pending: true,
        });
    }

    let later_signers: HashSet<Vec<u8>> = consignment
        .transitions
        .iter()
        .map(|t| pkid_bytes(&t.pkid))
        .collect();

    if holder != genesis_pkid {
        if holder.network != genesis_pkid.network {
            return Err(ReasonCode::NetworkMismatch);
        }
        let _ = load_setup_outputs(chain, &holder)?;
    }

    let mut holdings = Holdings::new();
    holdings.insert(holder, supply)?;
    let mut pending = false;

    for step in &consignment.transitions {
        if step.pkid.network != consignment.network {
            return Err(ReasonCode::NetworkMismatch);
        }
        let obs = collect_observed(chain, &step.pkid, policy)?;
        match check_claimed_close(&step.pkid, &step.message_bytes, &consignment.carriers, &obs)? {
            CloseCheck::Pending => {
                pending = true;
                break;
            }
            CloseCheck::Final => {}
        }
        let t = Transition::decode(&step.message_bytes)?;
        let Transition::Transfer {
            asset_id: tid,
            allocations,
        } = &t
        else {
            return Err(ReasonCode::UnknownTransitionType);
        };
        if tid != &aid {
            return Err(ReasonCode::AssetIdMismatch);
        }
        let balance = holdings.take(&step.pkid)?;
        check_transfer_rules(&step.pkid, balance, &aid, &t)?;
        for (recv, amt) in allocations {
            check_receiver(chain, &step.pkid, recv, &holdings, &later_signers, policy)?;
            holdings.insert(recv.clone(), *amt)?;
        }
        let _ = allocation_sum(allocations)?;
    }

    let mut owners = Vec::new();
    for (_, (pkid, amount)) in holdings.map {
        let obs = collect_observed(chain, &pkid, policy)?;
        let status = match obs.state {
            SealClose::Open => HoldingStatus::Open,
            SealClose::Closing => HoldingStatus::Closing,
            SealClose::Closed => {
                if pkid == genesis_pkid {
                    HoldingStatus::Closed
                } else {
                    HoldingStatus::ClosedUnknown
                }
            }
        };
        if status == HoldingStatus::Closing {
            pending = true;
        }
        owners.push(OwnerEntry {
            pkid,
            amount,
            status,
        });
    }
    owners.sort_by(|a, b| pkid_bytes(&a.pkid).cmp(&pkid_bytes(&b.pkid)));

    Ok(Resolution {
        asset_id: aid,
        supply,
        genesis_pkid,
        owners,
        pending,
    })
}

fn tx_to_hex(tx: &Transaction) -> String {
    let mut bin = Vec::new();
    tx.consensus_encode(&mut bin).expect("tx encode");
    hex::encode(bin)
}

fn tx_from_hex(s: &str) -> Result<Transaction, ReasonCode> {
    let raw = hex::decode(s.trim()).map_err(|_| ReasonCode::InvalidEncoding)?;
    Transaction::consensus_decode(&mut raw.as_slice()).map_err(|_| ReasonCode::InvalidEncoding)
}

pub fn consignment_to_json(c: &Consignment) -> ConsignmentJson {
    ConsignmentJson {
        network: network_name(c.network).to_string(),
        genesis: SignedJson {
            pkid: PkidJson::from_pkid(&c.genesis.pkid),
            message_hex: hex::encode(&c.genesis.message_bytes),
        },
        transitions: c
            .transitions
            .iter()
            .map(|t| SignedJson {
                pkid: PkidJson::from_pkid(&t.pkid),
                message_hex: hex::encode(&t.message_bytes),
            })
            .collect(),
        carriers_hex: c.carriers.iter().map(tx_to_hex).collect(),
    }
}

pub fn consignment_from_json(j: &ConsignmentJson) -> Result<Consignment, ReasonCode> {
    Ok(Consignment {
        network: parse_network_name(&j.network)?,
        genesis: SignedMessage {
            pkid: j.genesis.pkid.to_pkid()?,
            message_bytes: hex::decode(&j.genesis.message_hex)
                .map_err(|_| ReasonCode::InvalidEncoding)?,
        },
        transitions: j
            .transitions
            .iter()
            .map(|t| {
                Ok(SignedMessage {
                    pkid: t.pkid.to_pkid()?,
                    message_bytes: hex::decode(&t.message_hex)
                        .map_err(|_| ReasonCode::InvalidEncoding)?,
                })
            })
            .collect::<Result<Vec<_>, ReasonCode>>()?,
        carriers: j
            .carriers_hex
            .iter()
            .map(|h| tx_from_hex(h))
            .collect::<Result<Vec<_>, ReasonCode>>()?,
    })
}

/// Build an in-memory chain from setup transactions plus confirmed spends.
pub fn chain_from_txs(
    setups: impl IntoIterator<Item = Transaction>,
    confirmed: impl IntoIterator<Item = Transaction>,
    confirmations: u32,
) -> InMemoryChain {
    let mut chain = InMemoryChain::new();
    for tx in setups {
        chain.insert(tx, confirmations.max(1));
    }
    for tx in confirmed {
        chain.insert(tx, confirmations);
    }
    chain
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parameters::NetworkId;
    use bitcoin::hashes::Hash;

    #[test]
    fn missing_setup_is_setup_not_found() {
        let pkid = PublicKeyId {
            network: NetworkId::Regtest,
            setup_txid: Txid::from_byte_array([1; 32]),
            first_vout: 0,
            shard_count: SHARD_COUNT as u32,
            parameter_set_id: PARAMETER_SET_ID.to_string(),
        };
        let chain = InMemoryChain::new();
        let c = Consignment {
            network: NetworkId::Regtest,
            genesis: SignedMessage {
                pkid,
                message_bytes: Transition::Genesis {
                    supply: 1,
                    first_holder: None,
                }
                .encode(),
            },
            transitions: vec![],
            carriers: vec![],
        };
        assert_eq!(
            resolve(&c, &chain, ConfirmationPolicy::REGTEST).unwrap_err(),
            ReasonCode::SetupNotFound
        );
    }
}
