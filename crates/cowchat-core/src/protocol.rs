use serde::{Deserialize, Serialize};

/// Wire protocol version this build speaks. Sent in `RegisterPayload` and
/// advertised in the register reply. Bump when an older peer cannot safely
/// parse a new `Frame`/payload shape; raise [`MIN_SUPPORTED_PROTOCOL`] only once
/// the server genuinely drops support for an older shape.
pub const PROTOCOL_VERSION: u32 = 2;

/// Oldest protocol version the server still accepts. A client below this is
/// asked to upgrade rather than failing later with a confusing parse error.
/// A missing version in a register frame is treated as `1` (pre-versioning).
///
/// Equal to [`PROTOCOL_VERSION`] today, so v1 peers — and any client omitting
/// `protocol_version`, which is read as 1 — are refused at register. Deliberate:
/// v1 predates the version gate entirely.
///
/// **Bumping [`PROTOCOL_VERSION`] cannot signal unknown-frame tolerance.** The
/// server admits exactly `MIN_SUPPORTED_PROTOCOL..=PROTOCOL_VERSION`
/// (`server.rs`), so a client advertising a higher version is rejected by every
/// already-deployed server as "newer than this server".
///
/// A signal *is* available without a bump: `RegisterPayload.capabilities` is a
/// free-form list the server only logs and records — no whitelist, no
/// rejection — so a tolerant client can advertise `"frame-type-unknown"` and
/// every deployed v0.9.1 server accepts it unchanged. `cowchat-client` sends
/// that string on every register as of this change. The register reply is
/// likewise an open object, so a server can answer with its own
/// `capabilities` without breaking any deployed client. Nothing *checks* the
/// string yet: until a server does, treat a peer as intolerant.
///
/// Consequence for anyone adding a frame type: a peer that predates
/// [`FrameType::Unknown`] drops the line entirely, so a new *event* must be
/// optional and a new *reply type* will make such a peer block until timeout.
/// Capability negotiation in the register reply is the real fix; see the protocol
/// issues.
///
/// Raising this is a release-note event, not a routine change.
pub const MIN_SUPPORTED_PROTOCOL: u32 = 2;

/// Capability string a client sends in `RegisterPayload.capabilities` to say
/// it parses unknown frame types as [`FrameType::Unknown`] instead of dropping
/// the line. `cowchat-client` sends it on every register; no server checks it
/// yet. A future server gating a new frame type on tolerance must match this
/// exact string, so it lives here rather than as a literal in each crate. See
/// [`MIN_SUPPORTED_PROTOCOL`] for why this — not a version bump — is the only
/// usable signal.
pub const CAP_FRAME_TYPE_UNKNOWN: &str = "frame-type-unknown";

/// Every message on the wire is a Frame, serialized as a single line of JSON (NDJSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Frame {
    /// Optional correlation ID for request/response matching.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// For responses: which request this replies to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,

    /// The message type / command.
    #[serde(rename = "type")]
    pub frame_type: FrameType,

    /// Type-specific payload.
    #[serde(default = "default_payload")]
    pub payload: serde_json::Value,
}

fn default_payload() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

impl Frame {
    pub fn ok(reply_to: Option<&str>, payload: serde_json::Value) -> Self {
        Self {
            id: Some(uuid::Uuid::new_v4().to_string()),
            reply_to: reply_to.map(String::from),
            frame_type: FrameType::Ok,
            payload,
        }
    }

    pub fn error(reply_to: Option<&str>, error: crate::ErrorPayload) -> Self {
        Self {
            id: Some(uuid::Uuid::new_v4().to_string()),
            reply_to: reply_to.map(String::from),
            frame_type: FrameType::Error,
            payload: serde_json::to_value(error).unwrap_or_default(),
        }
    }

    pub fn event(frame_type: FrameType, payload: serde_json::Value) -> Self {
        Self {
            id: Some(uuid::Uuid::new_v4().to_string()),
            reply_to: None,
            frame_type,
            payload,
        }
    }

    pub fn pong(reply_to: Option<&str>) -> Self {
        Self {
            id: Some(uuid::Uuid::new_v4().to_string()),
            reply_to: reply_to.map(String::from),
            frame_type: FrameType::Pong,
            payload: serde_json::json!({}),
        }
    }

    /// Serialize this frame as a single NDJSON line (with trailing newline).
    pub fn to_line(&self) -> Result<String, serde_json::Error> {
        let mut line = serde_json::to_string(self)?;
        line.push('\n');
        Ok(line)
    }

    /// Parse a frame from a single line of JSON.
    pub fn from_line(line: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(line.trim())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FrameType {
    // Client -> Server commands
    Register,
    Ping,
    CreateRoom,
    JoinRoom,
    LeaveRoom,
    RenameRoom,
    DestroyRoom,
    SendMessage,
    EnrollNativeActorSeat,
    BindOwnerLog,
    GetOwnerLogBindingContext,
    EnrollNativeSourceSeat,
    ProvisionNativeAppendGrant,
    GetNativeRouteStatus,
    ClaimActorHandle,
    ReleaseActorHandle,
    RecoverActorHandle,
    SetActorWakeMode,
    ResolveActorHandle,
    GetHistory,
    ListRooms,
    ListAgents,
    RoomInfo,
    /// Room-scoped coordination: leases, heartbeats, fencing and readiness.
    RoomCoordination,
    RoomTip,
    PrepareRoomKey,
    AttestRoomKeySetup,
    ActivateRoomKey,
    GetRoomKeyContext,
    RelayRoomKeyOpen,

    // Voting commands (client -> server)
    CreateVote,
    CastVote,
    GetVoteStatus,
    ListVotes,

    // Election commands (client -> server)
    ElectLeader,
    DeclineElection,
    Decision,

    // Task commands (client -> server)
    AssignTask,
    UpdateTask,
    ListTasks,

    // Presence commands (client -> server)
    SetTyping,
    SetPresence,

    // Thinking pulse (client -> server, also broadcast back as event)
    Thinking,

    // Webhook subscriptions (client -> server)
    Subscribe,
    SubscribeActor,
    ClaimActorWork,
    CompleteActorWork,
    Unsubscribe,
    ListSubscriptions,
    EnableSubscription,

    // Room invites (client -> server)
    CreateInvite,
    RevokeInvite,
    ListInvites,
    RedeemInvite,

    // Server -> Client responses/events
    Ok,
    Error,
    Pong,
    MessageReceived,
    Mention,
    AgentJoined,
    AgentLeft,
    RoomCreated,
    RoomUpdated,
    /// Sent to an admitted session when a person approves it for a room.
    RoomApproved,
    SessionState,
    RoomDestroyed,
    PresenceUpdate,
    HistoryResult,
    RoomList,
    AgentList,
    RoomInfoResult,
    RoomTipResult,

    // Voting events (server -> client)
    VoteCreated,
    VoteResult,

    // Election events (server -> client)
    ElectionStarted,
    LeaderElected,
    LeaderCleared,
    DecisionMade,

    // Task events (server -> client)
    TaskAssigned,
    TaskUpdated,
    TaskList,

    // Presence events (server -> client)
    TypingIndicator,

    // Turn token events (server -> client)
    TurnChanged,

    /// Any frame type this build does not know.
    ///
    /// Without this, `Frame::from_line` rejects the whole line before dispatch
    /// sees it, so adding a frame type is a breaking change for every already
    /// deployed peer. With it, receivers degrade instead of failing:
    ///
    /// - **Unknown events are ignored.** Never disconnect over one.
    /// - **Unknown requests get a correlated error.** The server's dispatch
    ///   catch-all answers with `reply_to` set, so a caller fails fast rather
    ///   than blocking until timeout.
    ///
    /// Must stay a *unit* variant: `#[serde(other)]` is only permitted on one,
    /// so the original type string cannot be preserved here. A path that needs
    /// it should keep the undecoded `Frame`.
    #[serde(other)]
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_roundtrip() {
        let frame = Frame {
            id: Some("req-1".into()),
            reply_to: None,
            frame_type: FrameType::SendMessage,
            payload: serde_json::json!({"room_id": "lobby", "content": "hello"}),
        };

        let line = frame.to_line().unwrap();
        let parsed = Frame::from_line(&line).unwrap();
        assert_eq!(parsed.frame_type, FrameType::SendMessage);
        assert_eq!(parsed.id, Some("req-1".into()));
    }

    #[test]
    fn test_frame_type_serialization() {
        let json = serde_json::to_string(&FrameType::MessageReceived).unwrap();
        assert_eq!(json, "\"message_received\"");

        let parsed: FrameType = serde_json::from_str("\"join_room\"").unwrap();
        assert_eq!(parsed, FrameType::JoinRoom);

        let json = serde_json::to_string(&FrameType::RenameRoom).unwrap();
        assert_eq!(json, "\"rename_room\"");
        let parsed: FrameType = serde_json::from_str("\"room_updated\"").unwrap();
        assert_eq!(parsed, FrameType::RoomUpdated);
        assert_eq!(
            serde_json::to_string(&FrameType::RoomApproved).unwrap(),
            "\"room_approved\""
        );
        assert_eq!(
            serde_json::to_string(&FrameType::SessionState).unwrap(),
            "\"session_state\""
        );
    }

    #[test]
    fn room_owner_key_is_never_serialized() {
        let room = crate::Room {
            room_id: "private-room".into(),
            name: "private-room".into(),
            description: None,
            parent_id: None,
            created_at: chrono::Utc::now(),
            created_by: Some("creator".into()),
            visibility: "private".into(),
            owner_key: Some("bearer-secret".into()),
            last_activity: None,
            member_count: None,
            encrypted: false,
        };

        let frame = Frame::ok(Some("request"), serde_json::to_value(&room).unwrap());
        let encoded = frame.to_line().unwrap();
        assert!(!encoded.contains("owner_key"));
        assert!(!encoded.contains("bearer-secret"));
    }
}
