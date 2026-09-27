//! Public byte contract for a sender-signed focused native room route.
//!
//! The canonical protocol decoder in Core must accept these exact bytes.

pub const FOCUSED_SCOPE_V1: u8 = 2;
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
