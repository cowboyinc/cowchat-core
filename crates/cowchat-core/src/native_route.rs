//! Public byte contract for sender-signed native room routing intents.
//!
//! The canonical protocol decoder in Core must accept these exact bytes.

pub const FOCUSED_SCOPE_V1: u8 = 2;
pub const ROOM_WIDE_SCOPE_V1: u8 = 1;
const VERSION_V1: u8 = 1;
const SIGNATURE_DOMAIN_V1: &[u8] = b"cowboy/room-routing-intent/v1";
const NATIVE_INTENT_DOMAIN_V1: &[u8] = b"cowboy/native-room-intent/v1";
pub const NATIVE_INTENT_MAGIC_V1: &[u8; 8] = b"CBYRI001";

fn valid_handle(handle: &[u8]) -> bool {
    !handle.is_empty()
        && handle.len() <= 64
        && handle[0].is_ascii_lowercase()
        && handle[1..]
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

/// The sender signs its typed handle and already signed V1 routing intent as
/// one native Routing-lane declaration. Core decodes and verifies both layers.
pub fn native_room_intent_signing_preimage_v1(
    chain_instance_id: [u8; 32],
    room_id: [u8; 32],
    target_handle: &[u8],
    signed_intent: &[u8],
) -> Option<Vec<u8>> {
    if chain_instance_id == [0; 32]
        || room_id == [0; 32]
        || signed_intent.len() != 234
        || signed_intent[0] != VERSION_V1
        || signed_intent[1..33] != room_id
        || !match signed_intent[169] {
            ROOM_WIDE_SCOPE_V1 => target_handle.is_empty(),
            FOCUSED_SCOPE_V1 => valid_handle(target_handle),
            _ => false,
        }
    {
        return None;
    }
    let mut bytes = Vec::with_capacity(
        NATIVE_INTENT_DOMAIN_V1.len() + 1 + 32 + 32 + 1 + target_handle.len() + signed_intent.len(),
    );
    bytes.extend_from_slice(NATIVE_INTENT_DOMAIN_V1);
    bytes.push(VERSION_V1);
    bytes.extend_from_slice(&chain_instance_id);
    bytes.extend_from_slice(&room_id);
    bytes.push(target_handle.len() as u8);
    bytes.extend_from_slice(target_handle);
    bytes.extend_from_slice(signed_intent);
    Some(bytes)
}

pub fn native_room_intent_wire_bytes_v1(
    chain_instance_id: [u8; 32],
    room_id: [u8; 32],
    target_handle: &[u8],
    signed_intent: &[u8],
    signature: [u8; 64],
) -> Option<Vec<u8>> {
    let preimage = native_room_intent_signing_preimage_v1(
        chain_instance_id,
        room_id,
        target_handle,
        signed_intent,
    )?;
    let mut bytes = Vec::with_capacity(8 + preimage.len() - NATIVE_INTENT_DOMAIN_V1.len() + 64);
    bytes.extend_from_slice(NATIVE_INTENT_MAGIC_V1);
    bytes.extend_from_slice(&preimage[NATIVE_INTENT_DOMAIN_V1.len()..]);
    bytes.extend_from_slice(&signature);
    Some(bytes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FocusedRoutingIntentV1 {
    pub room_id: [u8; 32],
    pub source_seat_id: [u8; 32],
    pub target_seat_id: [u8; 32],
    pub message_id: [u8; 32],
    pub message_commitment: [u8; 32],
    pub claim_generation: u64,
    pub signature: [u8; 64],
}

impl FocusedRoutingIntentV1 {
    pub fn valid(&self) -> bool {
        self.room_id != [0; 32]
            && self.source_seat_id != [0; 32]
            && self.target_seat_id != [0; 32]
            && self.source_seat_id != self.target_seat_id
            && self.message_id != [0; 32]
            && self.message_commitment != [0; 32]
            && self.claim_generation != 0
    }

    pub fn signing_preimage(&self) -> Option<Vec<u8>> {
        self.valid().then(|| {
            let mut bytes = Vec::with_capacity(SIGNATURE_DOMAIN_V1.len() + 170);
            bytes.extend_from_slice(SIGNATURE_DOMAIN_V1);
            bytes.push(VERSION_V1);
            for field in [
                self.room_id,
                self.source_seat_id,
                self.target_seat_id,
                self.message_id,
                self.message_commitment,
            ] {
                bytes.extend_from_slice(&field);
            }
            bytes.extend_from_slice(&self.claim_generation.to_be_bytes());
            bytes.push(FOCUSED_SCOPE_V1);
            bytes
        })
    }

    pub fn wire_bytes(&self) -> Option<Vec<u8>> {
        self.valid().then(|| {
            let mut bytes = self.signing_preimage().unwrap();
            bytes.drain(..SIGNATURE_DOMAIN_V1.len());
            bytes.extend_from_slice(&self.signature);
            bytes
        })
    }
}

/// An ordinary room message names no actor. A relayer may later attach only
/// seats whose independently proved subscription was active at commit time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoomWideRoutingIntentV1 {
    pub room_id: [u8; 32],
    pub source_seat_id: [u8; 32],
    pub message_id: [u8; 32],
    pub message_commitment: [u8; 32],
    pub signature: [u8; 64],
}

impl RoomWideRoutingIntentV1 {
    pub fn valid(&self) -> bool {
        self.room_id != [0; 32]
            && self.source_seat_id != [0; 32]
            && self.message_id != [0; 32]
            && self.message_commitment != [0; 32]
    }

    pub fn signing_preimage(&self) -> Option<Vec<u8>> {
        self.valid().then(|| {
            let mut bytes = Vec::with_capacity(SIGNATURE_DOMAIN_V1.len() + 170);
            bytes.extend_from_slice(SIGNATURE_DOMAIN_V1);
            bytes.push(VERSION_V1);
            for field in [
                self.room_id,
                self.source_seat_id,
                [0; 32],
                self.message_id,
                self.message_commitment,
            ] {
                bytes.extend_from_slice(&field);
            }
            bytes.extend_from_slice(&0u64.to_be_bytes());
            bytes.push(ROOM_WIDE_SCOPE_V1);
            bytes
        })
    }

    pub fn wire_bytes(&self) -> Option<Vec<u8>> {
        self.valid().then(|| {
            let mut bytes = self.signing_preimage().unwrap();
            bytes.drain(..SIGNATURE_DOMAIN_V1.len());
            bytes.extend_from_slice(&self.signature);
            bytes
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn room_wide_intent_has_no_target_or_claim_generation() {
        let intent = RoomWideRoutingIntentV1 {
            room_id: [0x11; 32],
            source_seat_id: [0x12; 32],
            message_id: [0x13; 32],
            message_commitment: [0x14; 32],
            signature: [0x15; 64],
        };
        let wire = intent.wire_bytes().unwrap();
        assert_eq!(wire.len(), 234);
        assert_eq!(&wire[65..97], &[0; 32]);
        assert_eq!(&wire[161..169], &[0; 8]);
        assert_eq!(wire[169], ROOM_WIDE_SCOPE_V1);
        assert_eq!(&wire[170..], &intent.signature);
        assert!(!RoomWideRoutingIntentV1 {
            room_id: [0; 32],
            ..intent
        }
        .valid());
    }

    #[test]
    fn native_declaration_binds_chain_room_and_typed_handle() {
        let inner = FocusedRoutingIntentV1 {
            room_id: [0x11; 32],
            source_seat_id: [0x12; 32],
            target_seat_id: [0x13; 32],
            message_id: [0x14; 32],
            message_commitment: [0x15; 32],
            claim_generation: 1,
            signature: [0x16; 64],
        }
        .wire_bytes()
        .unwrap();
        let preimage = native_room_intent_signing_preimage_v1(
            [0x17; 32],
            [0x11; 32],
            b"financial_planner",
            &inner,
        )
        .unwrap();
        let wire = native_room_intent_wire_bytes_v1(
            [0x17; 32],
            [0x11; 32],
            b"financial_planner",
            &inner,
            [0x18; 64],
        )
        .unwrap();
        assert_eq!(&wire[..8], NATIVE_INTENT_MAGIC_V1);
        assert_eq!(
            &wire[8..wire.len() - 64],
            &preimage[NATIVE_INTENT_DOMAIN_V1.len()..]
        );
        assert_eq!(&wire[wire.len() - 64..], &[0x18; 64]);
        assert!(native_room_intent_signing_preimage_v1(
            [0; 32],
            [0x11; 32],
            b"financial_planner",
            &inner,
        )
        .is_none());
        assert!(native_room_intent_signing_preimage_v1(
            [0x17; 32],
            [0x19; 32],
            b"financial_planner",
            &inner,
        )
        .is_none());
        assert!(native_room_intent_signing_preimage_v1(
            [0x17; 32],
            [0x11; 32],
            b"bad-handle",
            &inner,
        )
        .is_none());
    }
}
