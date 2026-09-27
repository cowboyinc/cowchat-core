//! Public byte contract for sender-signed native room routing intents.
//!
//! The canonical protocol decoder in Core must accept these exact bytes.

use sha3::{Digest, Keccak256};

pub const FOCUSED_SCOPE_V1: u8 = 2;
pub const ROOM_WIDE_SCOPE_V1: u8 = 1;
const VERSION_V1: u8 = 1;
const SIGNATURE_DOMAIN_V1: &[u8] = b"cowboy/room-routing-intent/v1";
const NATIVE_INTENT_DOMAIN_V1: &[u8] = b"cowboy/native-room-intent/v1";
pub const NATIVE_INTENT_MAGIC_V1: &[u8; 8] = b"CBYRI001";
pub const NATIVE_CONTROL_MAGIC_V1: &[u8; 8] = b"CBYRC001";
const NATIVE_CONTROL_DOMAIN_V1: &[u8] = b"cowboy/native-room-control/v1";
const NATIVE_COMMAND_ID_DOMAIN_V1: &[u8] = b"cowboy/native-room-command-id/v1";

fn valid_handle(handle: &[u8]) -> bool {
    !handle.is_empty()
        && handle.len() <= 64
        && handle[0].is_ascii_lowercase()
        && handle[1..]
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

/// Stable native command identity for a hosted command ID. A retry must use
/// the original hosted command ID and exact signed control bytes.
pub fn native_room_command_id_v1(hosted_command_id: &str) -> Option<[u8; 32]> {
    if hosted_command_id.is_empty() || hosted_command_id.len() > 128 {
        return None;
    }
    let mut digest = Keccak256::new();
    digest.update(NATIVE_COMMAND_ID_DOMAIN_V1);
    digest.update((hosted_command_id.len() as u16).to_be_bytes());
    digest.update(hosted_command_id.as_bytes());
    Some(digest.finalize().into())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum NativeRoomControlKindV1 {
    Claim = 1,
    Release = 2,
    Recover = 3,
    WakeMode = 4,
}

/// Public preparation fields for a canonical native Routing control. The
/// actor controller key is separate from the seat record key held by Runner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeRoomControlV1 {
    pub kind: NativeRoomControlKindV1,
    pub chain_instance_id: [u8; 32],
    pub room_id: [u8; 32],
    pub command_id: [u8; 32],
    pub handle: Vec<u8>,
    pub seat_id: [u8; 32],
    pub generation: u64,
    /// 0 for claims, releases and recovery; 1 or 2 for wake mode.
    pub wake_mode: u8,
    pub controller_signing_key: [u8; 32],
}

impl NativeRoomControlV1 {
    pub fn valid(&self) -> bool {
        self.chain_instance_id != [0; 32]
            && self.room_id != [0; 32]
            && self.command_id != [0; 32]
            && self.seat_id != [0; 32]
            && self.generation != 0
            && match self.kind {
                NativeRoomControlKindV1::Claim | NativeRoomControlKindV1::Release => {
                    valid_handle(&self.handle)
                        && self.wake_mode == 0
                        && self.controller_signing_key != [0; 32]
                }
                NativeRoomControlKindV1::Recover => {
                    valid_handle(&self.handle)
                        && self.wake_mode == 0
                        && self.controller_signing_key == [0; 32]
                }
                NativeRoomControlKindV1::WakeMode => {
                    self.handle.is_empty()
                        && matches!(self.wake_mode, 1 | 2)
                        && self.controller_signing_key != [0; 32]
                }
            }
    }

    pub fn signing_preimage(&self) -> Option<Vec<u8>> {
        if !self.valid() {
            return None;
        }
        let mut bytes =
            Vec::with_capacity(NATIVE_CONTROL_DOMAIN_V1.len() + 172 + self.handle.len());
        bytes.extend_from_slice(NATIVE_CONTROL_DOMAIN_V1);
        bytes.push(1);
        bytes.push(self.kind as u8);
        bytes.extend_from_slice(&self.chain_instance_id);
        bytes.extend_from_slice(&self.room_id);
        bytes.extend_from_slice(&self.command_id);
        bytes.push(self.handle.len() as u8);
        bytes.extend_from_slice(&self.handle);
        bytes.extend_from_slice(&self.seat_id);
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.push(self.wake_mode);
        bytes.extend_from_slice(&self.controller_signing_key);
        Some(bytes)
    }

    /// Controller signature and owner signature are mutually exclusive. The
    /// unused signature must be all zeroes, as required by Core's decoder.
    pub fn wire_bytes(
        &self,
        controller_signature: [u8; 64],
        owner_signature: [u8; 65],
    ) -> Option<Vec<u8>> {
        let preimage = self.signing_preimage()?;
        match self.kind {
            NativeRoomControlKindV1::Recover
                if controller_signature != [0; 64] || owner_signature == [0; 65] =>
            {
                return None;
            }
            NativeRoomControlKindV1::Recover => {}
            _ if owner_signature != [0; 65] || controller_signature == [0; 64] => return None,
            _ => {}
        }
        let mut bytes =
            Vec::with_capacity(8 + preimage.len() - NATIVE_CONTROL_DOMAIN_V1.len() + 64 + 65);
        bytes.extend_from_slice(NATIVE_CONTROL_MAGIC_V1);
        bytes.extend_from_slice(&preimage[NATIVE_CONTROL_DOMAIN_V1.len()..]);
        bytes.extend_from_slice(&controller_signature);
        bytes.extend_from_slice(&owner_signature);
        Some(bytes)
    }
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
    fn native_control_bytes_keep_command_and_authority_separate() {
        let command_id = native_room_command_id_v1("prepared-command-id").unwrap();
        assert_eq!(
            command_id,
            native_room_command_id_v1("prepared-command-id").unwrap()
        );
        assert_ne!(
            command_id,
            native_room_command_id_v1("another-command-id").unwrap()
        );
        let claim = NativeRoomControlV1 {
            kind: NativeRoomControlKindV1::Claim,
            chain_instance_id: [0x21; 32],
            room_id: [0x22; 32],
            command_id,
            handle: b"financial_planner".to_vec(),
            seat_id: [0x23; 32],
            generation: 1,
            wake_mode: 0,
            controller_signing_key: [0x24; 32],
        };
        let preimage = claim.signing_preimage().unwrap();
        let wire = claim.wire_bytes([0x25; 64], [0; 65]).unwrap();
        assert_eq!(&wire[..8], NATIVE_CONTROL_MAGIC_V1);
        assert_eq!(
            &wire[8..wire.len() - 129],
            &preimage[NATIVE_CONTROL_DOMAIN_V1.len()..]
        );
        assert_eq!(&wire[wire.len() - 129..wire.len() - 65], &[0x25; 64]);
        assert!(claim.wire_bytes([0x25; 64], [0x26; 65]).is_none());
        assert!(NativeRoomControlV1 {
            kind: NativeRoomControlKindV1::Recover,
            controller_signing_key: [0; 32],
            ..claim.clone()
        }
        .wire_bytes([0; 64], [0x26; 65])
        .is_some());
        assert!(NativeRoomControlV1 {
            kind: NativeRoomControlKindV1::WakeMode,
            handle: Vec::new(),
            wake_mode: 2,
            ..claim
        }
        .wire_bytes([0x25; 64], [0; 65])
        .is_some());
    }

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
