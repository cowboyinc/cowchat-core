//! A shared plaintext commitment for the hosted and native encrypted views.
//! A fresh, secret 32-byte salt travels only inside each encrypted body. The
//! public ID contains a 224-bit digest, so it cannot test plaintext guesses
//! without decrypting a body first.

use sha2::{Digest, Sha256};

const PREFIX: &[u8; 4] = b"cwp2";
const DOMAIN: &[u8] = b"cowchat/paired-message-id/v2";

pub fn is_paired_message_id_v2(id: &[u8; 32]) -> bool {
    &id[..4] == PREFIX
}

/// The sender must generate a fresh random salt per message and keep it out
/// of public headers and metadata. Both encrypted views carry the same salt.
pub fn paired_message_id_v2(salt: &[u8; 32], plaintext: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(salt);
    hash.update(plaintext);
    let digest = hash.finalize();
    let mut id = [0u8; 32];
    id[..4].copy_from_slice(PREFIX);
    id[4..].copy_from_slice(&digest[..28]);
    id
}

pub fn verify_paired_message_id_v2(id: &[u8; 32], salt: &[u8; 32], plaintext: &[u8]) -> bool {
    is_paired_message_id_v2(id) && paired_message_id_v2(salt, plaintext) == *id
}

/// Encode the native body before encryption: secret salt followed by text.
pub fn paired_body_v2(salt: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let mut body = salt.to_vec();
    body.extend_from_slice(plaintext);
    body
}

/// Verify a decrypted native body before exposing its text to a consumer.
pub fn open_paired_body_v2<'a>(id: &[u8; 32], body: &'a [u8]) -> Option<([u8; 32], &'a [u8])> {
    let salt = body.get(..32)?.try_into().ok()?;
    let plaintext = &body[32..];
    verify_paired_message_id_v2(id, &salt, plaintext).then_some((salt, plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_id_vector_binds_secret_salt_and_plaintext() {
        // Computed independently using Python hashlib.sha256.
        let id = paired_message_id_v2(&[7; 32], b"forecast");
        assert_eq!(
            hex::encode(id),
            "637770323a1ece378ef61278e66fb30ff50cc588e96a357f2b924b4ba18668d7"
        );
        assert!(verify_paired_message_id_v2(&id, &[7; 32], b"forecast"));
        assert!(!verify_paired_message_id_v2(&id, &[8; 32], b"forecast"));
        assert!(!verify_paired_message_id_v2(&id, &[7; 32], b"different"));
        // The same guess with a different hidden salt has a different ID.
        assert_ne!(id, paired_message_id_v2(&[8; 32], b"forecast"));
        assert_ne!(&id[4..], &[7; 28]);
        let mut old = id;
        old[..4].copy_from_slice(b"cwp1");
        assert!(!is_paired_message_id_v2(&old));
        assert!(!verify_paired_message_id_v2(&old, &[7; 32], b"forecast"));
    }

    #[test]
    fn native_body_rejects_missing_salt_divergent_text_and_wrong_salt() {
        let id = paired_message_id_v2(&[7; 32], b"forecast");
        let body = paired_body_v2(&[7; 32], b"forecast");
        assert_eq!(
            open_paired_body_v2(&id, &body),
            Some(([7; 32], b"forecast".as_slice()))
        );
        for bad in [
            b"forecast".to_vec(),
            paired_body_v2(&[8; 32], b"forecast"),
            paired_body_v2(&[7; 32], b"different"),
        ] {
            assert!(open_paired_body_v2(&id, &bad).is_none());
        }
        let empty_id = paired_message_id_v2(&[7; 32], b"");
        assert_eq!(
            open_paired_body_v2(&empty_id, &[7; 32]),
            Some(([7; 32], b"".as_slice()))
        );
    }
}
