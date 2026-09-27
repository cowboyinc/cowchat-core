//! A shared plaintext commitment for the hosted and native encrypted views.
//! The nonce keeps repeated text from sharing an ID. The 128-bit truncated
//! digest is checked independently after each view is decrypted.

use sha2::{Digest, Sha256};

const PREFIX: &[u8; 4] = b"cwp1";
const DOMAIN: &[u8] = b"cowchat/paired-message-id/v1";

pub fn is_paired_message_id_v1(id: &[u8; 32]) -> bool {
    &id[..4] == PREFIX
}

pub fn paired_message_id_v1(nonce: [u8; 12], plaintext: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(nonce);
    hash.update(plaintext);
    let digest = hash.finalize();
    let mut id = [0u8; 32];
    id[..4].copy_from_slice(PREFIX);
    id[4..16].copy_from_slice(&nonce);
    id[16..].copy_from_slice(&digest[..16]);
    id
}

pub fn verify_paired_message_id_v1(id: &[u8; 32], plaintext: &[u8]) -> bool {
    is_paired_message_id_v1(id)
        && paired_message_id_v1(id[4..16].try_into().expect("fixed nonce"), plaintext) == *id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_and_nonce_are_bound() {
        let id = paired_message_id_v1([7; 12], b"forecast");
        assert!(verify_paired_message_id_v1(&id, b"forecast"));
        assert!(!verify_paired_message_id_v1(&id, b"different"));
        assert_ne!(id, paired_message_id_v1([8; 12], b"forecast"));
    }
}
