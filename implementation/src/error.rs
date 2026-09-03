use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid parameter: {0}")]
    InvalidParameter(&'static str),
    #[error("digit out of range: {0}")]
    DigitOutOfRange(u8),
    #[error("incomplete shard set")]
    IncompleteShardSet,
    #[error("duplicate shard spend")]
    DuplicateShard,
    #[error("branch vector does not match message digest")]
    DigestMismatch,
    #[error("script verification failed: {0}")]
    ScriptVerify(String),
    #[error("bitcoin consensus error: {0}")]
    BitcoinConsensus(String),
    #[error("insufficient input value for fees")]
    InsufficientValue,
    #[error("bank state: {0}")]
    BankState(&'static str),
    #[error("hex decode: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("bitcoin encode/decode: {0}")]
    Bitcoin(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
}
