//! Raw-key hosted room content. Local shared-secret crypto is a separate profile.
//! The authenticated plaintext binds room, key epoch and message ID; callers must
//! supply expected context rather than trusting fields from decrypted content.

use base64::engine::general_purpose::STANDARD_NO_PAD as B64;
use base64::Engine as _;
use chacha20poly1305::aead::{rand_core::RngCore, Aead, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use cowchat_crypto::paired_message_id::{is_paired_message_id_v2, verify_paired_message_id_v2};

const DOMAIN: &str = "cowchat-room-message-v1";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid room message context")]
    Context,
    #[error("cannot decrypt room message for this context")]
    Decrypt,
    #[error("secure randomness unavailable")]
    Random,
    #[error("cannot encode room message")]
    Encode,
}

pub struct Context<'a> {
    pub room_id: &'a str,
    pub key_epoch: u64,
    pub message_id: &'a str,
}

impl Context<'_> {
    fn validate(&self) -> Result<(), Error> {
        if self.room_id.is_empty()
            || self.message_id.is_empty()
            || self
                .message_id_bytes()
                .is_some_and(|id| id.starts_with(b"cwp1"))
        {
            return Err(Error::Context);
        }
        Ok(())
    }

    fn message_id_bytes(&self) -> Option<[u8; 32]> {
        hex::decode(self.message_id).ok()?.try_into().ok()
    }
}

/// Persist the result before send; uncertain retries must reuse these exact bytes.
pub fn encrypt(key: &[u8; 32], context: &Context<'_>, text: &str) -> Result<String, Error> {
    context.validate()?;
    if context
        .message_id_bytes()
        .is_some_and(|id| is_paired_message_id_v2(&id))
    {
        return Err(Error::Context);
    }
    let mut nonce = [0u8; 12];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| Error::Random)?;
    encrypt_with_nonce(key, context, text, None, &nonce)
}

/// The salt is encrypted with the text, never included in public metadata.
pub fn encrypt_paired(
    key: &[u8; 32],
    context: &Context<'_>,
    text: &str,
    salt: &[u8; 32],
) -> Result<String, Error> {
    context.validate()?;
    let id = context.message_id_bytes().ok_or(Error::Context)?;
    if !verify_paired_message_id_v2(&id, salt, text.as_bytes()) {
        return Err(Error::Context);
    }
    let mut nonce = [0u8; 12];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| Error::Random)?;
    encrypt_with_nonce(key, context, text, Some(salt), &nonce)
}

fn encrypt_with_nonce(
    key: &[u8; 32],
    context: &Context<'_>,
    text: &str,
    salt: Option<&[u8; 32]>,
    nonce: &[u8; 12],
) -> Result<String, Error> {
    let epoch = context.key_epoch.to_string();
    let salt_hex = salt.map(hex::encode);
    let mut fields = vec![DOMAIN, context.room_id, &epoch, context.message_id, text];
    if let Some(salt) = &salt_hex {
        fields.push(salt);
    }
    let plaintext = serde_json::to_vec(&fields).map_err(|_| Error::Encode)?;
    let ciphertext = ChaCha20Poly1305::new(key.into())
        .encrypt(Nonce::from_slice(nonce), plaintext.as_slice())
        .map_err(|_| Error::Encode)?;
    let mut bytes = nonce.to_vec();
    bytes.extend(ciphertext);
    Ok(format!("cow1:{}", B64.encode(bytes)))
}

pub fn decrypt(key: &[u8; 32], context: &Context<'_>, content: &str) -> Result<String, Error> {
    context.validate()?;
    let encoded = content.strip_prefix("cow1:").ok_or(Error::Decrypt)?;
    let bytes = B64.decode(encoded).map_err(|_| Error::Decrypt)?;
    if bytes.len() < 28 {
        return Err(Error::Decrypt);
    }
    let plaintext = ChaCha20Poly1305::new(key.into())
        .decrypt(Nonce::from_slice(&bytes[..12]), &bytes[12..])
        .map_err(|_| Error::Decrypt)?;
    let fields: Vec<String> = serde_json::from_slice(&plaintext).map_err(|_| Error::Decrypt)?;
    let paired_id = context.message_id_bytes().filter(is_paired_message_id_v2);
    if fields.len() != if paired_id.is_some() { 6 } else { 5 } {
        return Err(Error::Decrypt);
    }
    if fields[0] != DOMAIN
        || fields[1] != context.room_id
        || fields[2] != context.key_epoch.to_string()
        || fields[3] != context.message_id
    {
        return Err(Error::Decrypt);
    }
    if let Some(id) = paired_id {
        let salt: [u8; 32] = hex::decode(&fields[5])
            .map_err(|_| Error::Decrypt)?
            .try_into()
            .map_err(|_| Error::Decrypt)?;
        if !verify_paired_message_id_v2(&id, &salt, fields[4].as_bytes()) {
            return Err(Error::Decrypt);
        }
    }
    Ok(fields[4].clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> serde_json::Value {
        serde_json::from_str(include_str!("../../../fixtures/hosted-room-message.json")).unwrap()
    }

    fn key() -> [u8; 32] {
        std::array::from_fn(|i| i as u8)
    }

    #[test]
    fn independent_vectors_match_in_both_directions() {
        for vector in fixture()["vectors"].as_array().unwrap() {
            let context = Context {
                room_id: vector["room_id"].as_str().unwrap(),
                key_epoch: vector["key_epoch"].as_str().unwrap().parse().unwrap(),
                message_id: vector["message_id"].as_str().unwrap(),
            };
            let text = vector["text"].as_str().unwrap();
            let wire = vector["wire"].as_str().unwrap();
            assert_eq!(decrypt(&key(), &context, wire).unwrap(), text);
            let nonce = std::array::from_fn(|i| i as u8);
            assert_eq!(
                encrypt_with_nonce(&key(), &context, text, None, &nonce).unwrap(),
                wire
            );
        }
    }

    #[test]
    fn rejects_bad_payloads_and_substituted_context() {
        let context = Context {
            room_id: "room-test",
            key_epoch: 0,
            message_id: "message-1",
        };
        let fixture = fixture();
        for invalid in fixture["invalid"].as_array().unwrap() {
            assert!(decrypt(&key(), &context, invalid["wire"].as_str().unwrap()).is_err());
        }
        let wire = fixture["vectors"][0]["wire"].as_str().unwrap();
        for wrong in [
            Context {
                room_id: "other",
                ..context
            },
            Context {
                key_epoch: 1,
                ..context
            },
            Context {
                message_id: "other",
                ..context
            },
        ] {
            assert!(decrypt(&key(), &wrong, wire).is_err());
        }
        assert!(decrypt(&[0; 32], &context, wire).is_err());
        assert!(decrypt(&key(), &context, &format!("{wire}=")).is_err());
        assert!(decrypt(&key(), &context, &format!("{wire}\n")).is_err());
        let mut damaged = B64.decode(wire.strip_prefix("cow1:").unwrap()).unwrap();
        *damaged.last_mut().unwrap() ^= 1;
        assert!(decrypt(&key(), &context, &format!("cow1:{}", B64.encode(damaged))).is_err());
        let unicode_wire = fixture["vectors"][2]["wire"].as_str().unwrap();
        assert!(decrypt(
            &key(),
            &Context {
                room_id: "room-e\u{0301}",
                key_epoch: 1,
                message_id: "message-é"
            },
            unicode_wire
        )
        .is_err());
        assert!(decrypt(
            &key(),
            &Context {
                room_id: "room-é",
                key_epoch: 1,
                message_id: "message-e\u{0301}"
            },
            unicode_wire
        )
        .is_err());
    }

    #[test]
    fn paired_body_requires_the_hidden_salt_and_matching_text() {
        let salt = [7; 32];
        let id = hex::encode(cowchat_crypto::paired_message_id::paired_message_id_v2(
            &salt,
            b"forecast",
        ));
        let context = Context {
            room_id: "room-test",
            key_epoch: 1,
            message_id: &id,
        };
        let wire = encrypt_paired(&key(), &context, "forecast", &salt).unwrap();
        assert_eq!(decrypt(&key(), &context, &wire).unwrap(), "forecast");
        // Public sender helpers refuse unbound or divergent paired views.
        assert!(encrypt(&key(), &context, "forecast").is_err());
        assert!(encrypt_paired(&key(), &context, "other", &salt).is_err());
        assert!(encrypt_paired(&key(), &context, "forecast", &[8; 32]).is_err());
        // Even a sender who constructs authenticated ciphertext directly
        // cannot pass the receiver with missing, changed or crossed salt/text.
        for (text, salt) in [
            ("forecast", None),
            ("forecast", Some(&[8; 32])),
            ("other", Some(&salt)),
        ] {
            let bad = encrypt_with_nonce(&key(), &context, text, salt, &[1; 12]).unwrap();
            assert!(decrypt(&key(), &context, &bad).is_err());
        }
        let unpaired = Context {
            message_id: "ordinary",
            ..context
        };
        let extra =
            encrypt_with_nonce(&key(), &unpaired, "forecast", Some(&salt), &[1; 12]).unwrap();
        assert!(decrypt(&key(), &unpaired, &extra).is_err());
        let old_id = id.replacen("63777032", "63777031", 1);
        let old = Context {
            message_id: &old_id,
            ..context
        };
        assert!(encrypt(&key(), &old, "forecast").is_err());
        assert!(decrypt(&key(), &old, &wire).is_err());
    }

    #[test]
    fn fresh_nonces_and_empty_context_rejection() {
        let context = Context {
            room_id: "room-test",
            key_epoch: 0,
            message_id: "message-1",
        };
        let a = encrypt(&key(), &context, "Hello 🐎").unwrap();
        let b = encrypt(&key(), &context, "Hello 🐎").unwrap();
        assert_ne!(a, b);
        assert_eq!(decrypt(&key(), &context, &a).unwrap(), "Hello 🐎");
        assert!(encrypt(
            &key(),
            &Context {
                room_id: "",
                ..context
            },
            "text"
        )
        .is_err());
        assert!(encrypt(
            &key(),
            &Context {
                message_id: "",
                ..context
            },
            "text"
        )
        .is_err());
    }
}
