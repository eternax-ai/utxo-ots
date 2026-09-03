//! Durable bank state machine.
//!
//! Preimages must not leave the device before the bank is marked `Exposed`.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BankStatus {
    Generated,
    Funding,
    Funded,
    Signing,
    Exposed,
    Publishing,
    PartiallyConfirmed,
    Confirmed,
    Poisoned,
}

impl BankStatus {
    pub fn can_begin_sign(self) -> bool {
        matches!(self, Self::Funded)
    }

    pub fn is_terminal_failure(self) -> bool {
        matches!(self, Self::Poisoned)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BankRecord {
    pub id: String,
    pub status: BankStatus,
    pub key_nonce_hex: String,
    pub setup_txid_hex: Option<String>,
    pub first_vout: Option<u32>,
    pub message_domain_tag: String,
    /// Hex SHA-256 of the message once exposed (no raw preimages stored here).
    pub exposed_message_hash_hex: Option<String>,
}

impl BankRecord {
    pub fn new(id: impl Into<String>, key_nonce_hex: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            status: BankStatus::Generated,
            key_nonce_hex: key_nonce_hex.into(),
            setup_txid_hex: None,
            first_vout: None,
            message_domain_tag: "spend-to-sign/message/v1".to_string(),
            exposed_message_hash_hex: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BankStore {
    path: PathBuf,
    record: BankRecord,
}

impl BankStore {
    pub fn create(dir: impl AsRef<Path>, record: BankRecord) -> Result<Self, Error> {
        let dir = dir.as_ref();
        fs::create_dir_all(dir)?;
        let path = dir.join(format!("{}.json", record.id));
        if path.exists() {
            return Err(Error::BankState("bank record already exists"));
        }
        let store = Self { path, record };
        store.persist()?;
        Ok(store)
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref().to_path_buf();
        let text = fs::read_to_string(&path)?;
        let record: BankRecord = serde_json::from_str(&text)?;
        Ok(Self { path, record })
    }

    pub fn record(&self) -> &BankRecord {
        &self.record
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn persist(&self) -> Result<(), Error> {
        let tmp = self.path.with_extension("json.tmp");
        let text = serde_json::to_string_pretty(&self.record)?;
        fs::write(&tmp, text)?;
        fs::rename(&tmp, &self.path)?;
        // Best-effort durability on Unix.
        if let Ok(file) = fs::File::open(&self.path) {
            let _ = file.sync_all();
        }
        Ok(())
    }

    pub fn set_funding(&mut self) -> Result<(), Error> {
        self.transition(&[BankStatus::Generated], BankStatus::Funding)
    }

    pub fn set_funded(&mut self, setup_txid_hex: String, first_vout: u32) -> Result<(), Error> {
        match self.record.status {
            BankStatus::Funding | BankStatus::Generated => {
                self.record.setup_txid_hex = Some(setup_txid_hex);
                self.record.first_vout = Some(first_vout);
                self.record.status = BankStatus::Funded;
                self.persist()
            }
            _ => Err(Error::BankState("cannot mark funded from current status")),
        }
    }

    /// Exclusive lease before computing openings.
    pub fn begin_signing(&mut self) -> Result<(), Error> {
        self.transition(&[BankStatus::Funded], BankStatus::Signing)
    }

    /// Durable mark that preimages may leave the device. Must precede returning
    /// openings to a caller.
    pub fn mark_exposed(&mut self, message_hash_hex: String) -> Result<(), Error> {
        match self.record.status {
            BankStatus::Signing | BankStatus::Funded => {
                self.record.exposed_message_hash_hex = Some(message_hash_hex);
                self.record.status = BankStatus::Exposed;
                self.persist()
            }
            BankStatus::Exposed => Ok(()),
            _ => Err(Error::BankState("cannot expose from current status")),
        }
    }

    pub fn set_publishing(&mut self) -> Result<(), Error> {
        self.transition(
            &[BankStatus::Exposed, BankStatus::PartiallyConfirmed],
            BankStatus::Publishing,
        )
    }

    pub fn set_partially_confirmed(&mut self) -> Result<(), Error> {
        self.transition(
            &[BankStatus::Publishing, BankStatus::Exposed],
            BankStatus::PartiallyConfirmed,
        )
    }

    pub fn set_confirmed(&mut self) -> Result<(), Error> {
        self.transition(
            &[
                BankStatus::Publishing,
                BankStatus::PartiallyConfirmed,
                BankStatus::Exposed,
            ],
            BankStatus::Confirmed,
        )
    }

    pub fn poison(&mut self, _reason: &str) -> Result<(), Error> {
        self.record.status = BankStatus::Poisoned;
        self.persist()
    }

    fn transition(&mut self, from: &[BankStatus], to: BankStatus) -> Result<(), Error> {
        if !from.contains(&self.record.status) {
            return Err(Error::BankState("illegal state transition"));
        }
        self.record.status = to;
        self.persist()
    }
}

/// Helper: refuse to produce openings unless the store is leased and then mark exposed.
pub fn expose_for_sign(
    store: &mut BankStore,
    message_hash_hex: String,
) -> Result<(), Error> {
    if store.record().status == BankStatus::Funded {
        store.begin_signing()?;
    }
    if store.record().status != BankStatus::Signing
        && store.record().status != BankStatus::Exposed
    {
        return Err(Error::BankState("bank not in signing/exposed state"));
    }
    store.mark_exposed(message_hash_hex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_dir() -> PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("sts-bank-{n}"))
    }

    #[test]
    fn expose_before_reuse_blocked() {
        let dir = tmp_dir();
        let mut store = BankStore::create(&dir, BankRecord::new("b1", "00".repeat(16))).unwrap();
        store.set_funded("aa".repeat(32), 0).unwrap();
        expose_for_sign(&mut store, "deadbeef".into()).unwrap();
        assert_eq!(store.record().status, BankStatus::Exposed);
        // Cannot begin a second sign from exposed
        assert!(store.begin_signing().is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn reopen_preserves_exposed() {
        let dir = tmp_dir();
        let path = {
            let mut store = BankStore::create(&dir, BankRecord::new("b2", "11".repeat(16))).unwrap();
            store.set_funded("bb".repeat(32), 0).unwrap();
            expose_for_sign(&mut store, "cafebabe".into()).unwrap();
            store.path().to_path_buf()
        };
        let reopened = BankStore::open(&path).unwrap();
        assert_eq!(reopened.record().status, BankStatus::Exposed);
        let _ = fs::remove_dir_all(dir);
    }
}
