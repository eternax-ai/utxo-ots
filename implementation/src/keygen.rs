//! HMAC-SHA256 key generation for one-time digit secrets.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::error::Error;
use crate::parameters::{
    ALTERNATIVES, DIGITS_PER_SHARD, KEY_NONCE_LEN, LOGICAL_DIGITS, PREIMAGE_LEN, SECRET_DOMAIN,
    SHARD_COUNT,
};
use crate::script::{ShardScript, build_shard_script};

type HmacSha256 = Hmac<Sha256>;

/// One signing bank: secrets, commitments, and per-shard witness scripts.
#[derive(Clone)]
pub struct SigningBank {
    pub key_nonce: [u8; KEY_NONCE_LEN],
    /// `secrets[digit][alternative]`
    pub secrets: Vec<[[u8; PREIMAGE_LEN]; ALTERNATIVES]>,
    /// `commitments[digit][alternative] = SHA256(secret)`
    pub commitments: Vec<[[u8; 32]; ALTERNATIVES]>,
    pub shard_scripts: Vec<ShardScript>,
}

impl std::fmt::Debug for SigningBank {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningBank")
            .field("key_nonce", &hex::encode(self.key_nonce))
            .field("digits", &self.secrets.len())
            .field("shards", &self.shard_scripts.len())
            .finish_non_exhaustive()
    }
}

fn derive_secret(
    master: &[u8],
    key_nonce: &[u8],
    digit: u16,
    alternative: u8,
) -> [u8; PREIMAGE_LEN] {
    let mut mac = HmacSha256::new_from_slice(master).expect("HMAC accepts any key length");
    mac.update(SECRET_DOMAIN);
    mac.update(key_nonce);
    mac.update(&digit.to_be_bytes());
    mac.update(&[alternative]);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; PREIMAGE_LEN];
    out.copy_from_slice(&result);
    out
}

impl SigningBank {
    /// Derive a full bank from master seed `K` and random `key_nonce`.
    pub fn generate(master: &[u8], key_nonce: [u8; KEY_NONCE_LEN]) -> Result<Self, Error> {
        if master.is_empty() {
            return Err(Error::InvalidParameter("empty master seed"));
        }
        let mut secrets = Vec::with_capacity(LOGICAL_DIGITS);
        let mut commitments = Vec::with_capacity(LOGICAL_DIGITS);
        for i in 0..LOGICAL_DIGITS {
            let mut s_row = [[0u8; PREIMAGE_LEN]; ALTERNATIVES];
            let mut c_row = [[0u8; 32]; ALTERNATIVES];
            for j in 0..ALTERNATIVES {
                let s = derive_secret(master, &key_nonce, i as u16, j as u8);
                c_row[j] = Sha256::digest(s).into();
                s_row[j] = s;
            }
            secrets.push(s_row);
            commitments.push(c_row);
        }
        let shard_scripts = setup_scripts(&commitments)?;
        Ok(Self {
            key_nonce,
            secrets,
            commitments,
            shard_scripts,
        })
    }

    pub fn shard_script(&self, shard: usize) -> &ShardScript {
        &self.shard_scripts[shard]
    }

    /// Reveal preimages and selector bits for a global digit vector.
    pub fn openings_for_digits(&self, digits: &[u8]) -> Result<Vec<DigitOpening>, Error> {
        if digits.len() != LOGICAL_DIGITS {
            return Err(Error::InvalidParameter("expected 192 digits"));
        }
        let mut out = Vec::with_capacity(LOGICAL_DIGITS);
        for (i, &d) in digits.iter().enumerate() {
            if d >= RADIX_U8 {
                return Err(Error::DigitOutOfRange(d));
            }
            out.push(DigitOpening {
                digit_index: i,
                choice: d,
                preimage: self.secrets[i][d as usize],
                low_bit: d & 1,
                high_bit: (d >> 1) & 1,
            });
        }
        Ok(out)
    }
}

const RADIX_U8: u8 = 4;

#[derive(Debug, Clone, Copy)]
pub struct DigitOpening {
    pub digit_index: usize,
    pub choice: u8,
    pub preimage: [u8; PREIMAGE_LEN],
    pub low_bit: u8,
    pub high_bit: u8,
}

/// Build the 12 shard scripts from the full commitment table.
pub fn setup_scripts(
    commitments: &[[[u8; 32]; ALTERNATIVES]],
) -> Result<Vec<ShardScript>, Error> {
    if commitments.len() != LOGICAL_DIGITS {
        return Err(Error::InvalidParameter("commitment table size"));
    }
    let mut scripts = Vec::with_capacity(SHARD_COUNT);
    for shard in 0..SHARD_COUNT {
        let start = shard * DIGITS_PER_SHARD;
        let end = start + DIGITS_PER_SHARD;
        let digit_commits: Vec<[[u8; 32]; ALTERNATIVES]> = commitments[start..end].to_vec();
        scripts.push(build_shard_script(&digit_commits)?);
    }
    Ok(scripts)
}
