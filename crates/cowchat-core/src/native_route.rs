//! Public byte contract for sender-signed native room routing intents.
//!
//! The canonical protocol decoder in Core must accept these exact bytes.

pub const FOCUSED_SCOPE_V1: u8 = 2;
pub const ROOM_WIDE_SCOPE_V1: u8 = 1;
const VERSION_V1: u8 = 1;
const SIGNATURE_DOMAIN_V1: &[u8] = b"cowboy/room-routing-intent/v1";

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
}
