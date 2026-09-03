//! Detached-message digest and base-4 digit expansion.

use sha2::{Digest, Sha384};

use crate::error::Error;
use crate::parameters::{LOGICAL_DIGITS, MESSAGE_DOMAIN, PublicKeyId};

/// `SHA384(domain || Encode(pkid) || EncodeLength(M) || M)` then 192 base-4 digits.
pub fn encode_message(pkid: &PublicKeyId, message: &[u8]) -> [u8; 48] {
    let mut hasher = Sha384::new();
    hasher.update(MESSAGE_DOMAIN);
    hasher.update(pkid.encode());
    hasher.update(&(message.len() as u64).to_be_bytes());
    hasher.update(message);
    hasher.finalize().into()
}

/// Big-endian bit order within the digest: digit 0 is the two MSBs of byte 0.
pub fn digest_digits(digest: &[u8; 48]) -> [u8; LOGICAL_DIGITS] {
    let mut digits = [0u8; LOGICAL_DIGITS];
    let mut di = 0;
    for byte in digest {
        // four base-4 digits per byte, MSB first
        digits[di] = (byte >> 6) & 0b11;
        digits[di + 1] = (byte >> 4) & 0b11;
        digits[di + 2] = (byte >> 2) & 0b11;
        digits[di + 3] = byte & 0b11;
        di += 4;
    }
    debug_assert_eq!(di, LOGICAL_DIGITS);
    digits
}

pub fn message_digits(pkid: &PublicKeyId, message: &[u8]) -> [u8; LOGICAL_DIGITS] {
    digest_digits(&encode_message(pkid, message))
}

pub fn parse_selectors(low: u8, high: u8) -> Result<u8, Error> {
    if low > 1 || high > 1 {
        return Err(Error::InvalidParameter("selector not boolean"));
    }
    Ok(low | (high << 1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use crate::parameters::{NetworkId, PARAMETER_SET_ID, SHARD_COUNT};

    #[test]
    fn digit_count_and_roundtrip_bits() {
        let pkid = PublicKeyId {
            network: NetworkId::Regtest,
            setup_txid: bitcoin::Txid::from_byte_array([9u8; 32]),
            first_vout: 0,
            shard_count: SHARD_COUNT as u32,
            parameter_set_id: PARAMETER_SET_ID.to_string(),
        };
        let d = encode_message(&pkid, b"hello");
        let digits = digest_digits(&d);
        assert_eq!(digits.len(), 192);
        // reconstruct first byte
        let b0 = (digits[0] << 6) | (digits[1] << 4) | (digits[2] << 2) | digits[3];
        assert_eq!(b0, d[0]);
    }
}
