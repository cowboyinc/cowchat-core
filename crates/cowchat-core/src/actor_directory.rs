//! Canonical bytes signed for room-local actor names and wake preferences.

use crate::ActorWakeMode;

fn signed_preimage(
    action: &[u8],
    room_id: &str,
    command_id: &str,
    handle: &str,
    agent_id: &str,
    seat_id: &[u8; 32],
    generation: u64,
    mode: Option<ActorWakeMode>,
) -> Vec<u8> {
    let mut bytes = b"cowchat/actor-directory/v1\0".to_vec();
    for field in [
        action,
        room_id.as_bytes(),
        command_id.as_bytes(),
        handle.as_bytes(),
        agent_id.as_bytes(),
    ] {
        bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
        bytes.extend_from_slice(field);
    }
    bytes.extend_from_slice(seat_id);
    bytes.extend_from_slice(&generation.to_be_bytes());
    bytes.push(match mode {
        None => 0,
        Some(ActorWakeMode::MentionsOnly) => 1,
        Some(ActorWakeMode::AllMessages) => 2,
    });
    bytes
}

pub fn claim_preimage(
    room_id: &str,
    command_id: &str,
    handle: &str,
    agent_id: &str,
    seat_id: &[u8; 32],
    generation: u64,
) -> Vec<u8> {
    signed_preimage(
        b"claim", room_id, command_id, handle, agent_id, seat_id, generation, None,
    )
}

pub fn release_preimage(
    room_id: &str,
    command_id: &str,
    handle: &str,
    agent_id: &str,
    seat_id: &[u8; 32],
    generation: u64,
) -> Vec<u8> {
    signed_preimage(
        b"release", room_id, command_id, handle, agent_id, seat_id, generation, None,
    )
}

pub fn wake_mode_preimage(
    room_id: &str,
    command_id: &str,
    agent_id: &str,
    seat_id: &[u8; 32],
    generation: u64,
    mode: ActorWakeMode,
) -> Vec<u8> {
    signed_preimage(
        b"wake-mode",
        room_id,
        command_id,
        "",
        agent_id,
        seat_id,
        generation,
        Some(mode),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_bytes_bind_room_command_actor_generation_and_mode() {
        let base = claim_preimage("room-a", "one", "financial_planner", "actor-a", &[1; 32], 1);
        assert_ne!(
            base,
            claim_preimage("room-b", "one", "financial_planner", "actor-a", &[1; 32], 1)
        );
        assert_ne!(
            base,
            claim_preimage("room-a", "two", "financial_planner", "actor-a", &[1; 32], 1)
        );
        assert_ne!(
            base,
            claim_preimage("room-a", "one", "financial_planner", "actor-b", &[1; 32], 1)
        );
        assert_ne!(
            base,
            claim_preimage("room-a", "one", "financial_planner", "actor-a", &[1; 32], 2)
        );
        assert_ne!(
            base,
            release_preimage("room-a", "one", "financial_planner", "actor-a", &[1; 32], 1)
        );
        assert_ne!(
            wake_mode_preimage(
                "room-a",
                "one",
                "actor-a",
                &[1; 32],
                1,
                ActorWakeMode::MentionsOnly
            ),
            wake_mode_preimage(
                "room-a",
                "one",
                "actor-a",
                &[1; 32],
                1,
                ActorWakeMode::AllMessages
            )
        );
    }
}
