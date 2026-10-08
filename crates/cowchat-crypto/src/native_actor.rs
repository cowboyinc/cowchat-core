//! Strict Cowchat v3 envelope profile for chain-authorized source seats.
//!
//! The caller must obtain every expected field and the record-signing key from
//! one finalized room-authority proof. Actor and human seats use the same
//! signature boundary because chain seat admission has already verified their
//! controller authorization. Gateway ingress has an external-author profile:
//! its channel reference must match finalized Gateway seat authority and its
//! signed sender identifier remains an assertion by that door, never a Human seat.
use crate::{canonical, envelope, fields::Fields, Error, Result};
use ciborium::value::Value;
use ed25519_dalek::SigningKey;
use std::io::Cursor;

const HEADER_FIELDS: &[&str] = &[
    "v",
    "message_id",
    "chain_id",
    "room",
    "seat",
    "role",
    "via",
    "via_sender",
    "class",
    "reply_to",
    "mentions",
    "wake_hint",
    "gen",
    "cert",
    "nonce",
];

/// Maximum accepted outer tuple size. The encrypted body and canonical header
/// retain their own tighter bounds.
pub const MAX_SEALED_RECORD_BYTES: usize = envelope::MAX_BODY_BYTES + canonical::MAX_BYTES + 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceSeatKindV1 {
    Actor,
    Human,
    Gateway,
}

impl SourceSeatKindV1 {
    fn header_role(self) -> Result<&'static str> {
        match self {
            Self::Actor => Ok("actor"),
            Self::Human => Ok("human"),
            Self::Gateway => Ok("external"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedSourceSeatRecordV1 {
    pub chain_id: u64,
    pub room_id: [u8; 32],
    pub source_seat_id: [u8; 32],
    pub source_seat_kind: SourceSeatKindV1,
    /// Required only for Gateway seats, from the finalized seat gateway_ref.
    pub gateway_ref: Option<String>,
    pub source_key_binding_commitment: [u8; 32],
    pub key_generation: u64,
    /// A routed actor message must authenticate the target mention in the
    /// signed header before the body is decrypted.
    pub target_seat_id: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedRoomWideSourceSeatRecordV1 {
    pub chain_id: u64,
    pub room_id: [u8; 32],
    pub source_seat_id: [u8; 32],
    pub source_seat_kind: SourceSeatKindV1,
    /// Required only for Gateway seats, from the finalized seat gateway_ref.
    pub gateway_ref: Option<String>,
    pub source_key_binding_commitment: [u8; 32],
    pub key_generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenedSourceSeatRecordV1 {
    pub attribution: Option<GatewayAttributionV1>,
    pub message_id: [u8; 32],
    pub reply_to: Option<[u8; 32]>,
    pub mentions: Vec<[u8; 32]>,
    pub plaintext: Vec<u8>,
    /// Available only after decryption and commitment verification.
    pub paired_salt: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedSourceSeatHeaderV1 {
    pub attribution: Option<GatewayAttributionV1>,
    pub message_id: [u8; 32],
    pub reply_to: Option<[u8; 32]>,
    pub mentions: Vec<[u8; 32]>,
}

/// External identities are authenticated assertions by a Gateway key. They
/// confer no Human, owner, wallet or actor authority on the external sender.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayAttributionV1 {
    pub gateway_ref: String,
    pub sender_id: String,
}

/// One door-authored message, focused on one actor or posted room-wide.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayMessageHeaderV1 {
    pub message: HumanRoomWideHeaderV1,
    pub target_seat_id: Option<[u8; 32]>,
    pub attribution: GatewayAttributionV1,
}

/// A channel/sender reference is an opaque, bounded identifier, not display
/// text. Providers may use namespaced IDs such as telegram:-10012345.
pub fn validate_gateway_identifier_v1(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/@+-".contains(&b))
    {
        return Err(Error::Scope);
    }
    Ok(())
}

fn validate_source_profile(kind: SourceSeatKindV1, gateway_ref: Option<&str>) -> Result<()> {
    match (kind, gateway_ref) {
        (SourceSeatKindV1::Gateway, Some(reference)) => validate_gateway_identifier_v1(reference),
        (SourceSeatKindV1::Actor | SourceSeatKindV1::Human, None) => Ok(()),
        _ => Err(Error::Scope),
    }
}

fn check_attribution(
    fields: &Fields,
    kind: SourceSeatKindV1,
    gateway_ref: Option<&str>,
) -> Result<Option<GatewayAttributionV1>> {
    validate_source_profile(kind, gateway_ref)?;
    let via = fields.nullable_text("via")?;
    let sender = fields.nullable_text("via_sender")?;
    match (gateway_ref, via, sender) {
        (None, None, None) => Ok(None),
        (Some(expected), Some(reference), Some(sender_id)) if reference == expected => {
            validate_gateway_identifier_v1(&sender_id)?;
            Ok(Some(GatewayAttributionV1 {
                gateway_ref: reference,
                sender_id,
            }))
        }
        _ => Err(Error::Scope),
    }
}

pub fn gateway_message_header_v1(message: &GatewayMessageHeaderV1) -> Result<Vec<u8>> {
    validate_gateway_identifier_v1(&message.attribution.gateway_ref)?;
    validate_gateway_identifier_v1(&message.attribution.sender_id)?;
    let source = &message.message;
    let direct = match message.target_seat_id {
        Some(target_seat_id) => human_focused_header_v1(&HumanFocusedHeaderV1 {
            chain_id: source.chain_id,
            room_id: source.room_id,
            seat_id: source.seat_id,
            key_binding_commitment: source.key_binding_commitment,
            key_generation: source.key_generation,
            message_id: source.message_id,
            target_seat_id,
            reply_to: source.reply_to,
        })?,
        None => human_room_wide_header_v1(source)?,
    };
    let Value::Map(mut fields) = canonical::decode(&direct)? else {
        return Err(Error::Schema);
    };
    for (key, value) in &mut fields {
        match key.as_text() {
            Some("role") => *value = Value::Text("external".into()),
            Some("via") => *value = Value::Text(message.attribution.gateway_ref.clone()),
            Some("via_sender") => *value = Value::Text(message.attribution.sender_id.clone()),
            _ => {}
        }
    }
    canonical::encode(Value::Map(fields))
}

pub fn seal_gateway_message_v1(
    message: &GatewayMessageHeaderV1,
    generation_secret: &[u8; 32],
    plaintext: &[u8],
    signing_seed: &[u8; 32],
    expected_record_signing_key: &[u8; 32],
) -> Result<Vec<u8>> {
    if SigningKey::from_bytes(signing_seed)
        .verifying_key()
        .to_bytes()
        != *expected_record_signing_key
    {
        return Err(Error::Authority);
    }
    envelope::seal(
        &gateway_message_header_v1(message)?,
        generation_secret,
        plaintext,
        signing_seed,
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActorReplyHeaderV1 {
    pub chain_id: u64,
    pub room_id: [u8; 32],
    pub seat_id: [u8; 32],
    pub key_binding_commitment: [u8; 32],
    pub key_generation: u64,
    pub message_id: [u8; 32],
    pub reply_to: [u8; 32],
}

/// The source-seat fields of a focused human message. The caller must obtain
/// these values from finalized authority and retain the sealed result for
/// retry; this constructor does not establish room membership on its own.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanFocusedHeaderV1 {
    pub chain_id: u64,
    pub room_id: [u8; 32],
    pub seat_id: [u8; 32],
    pub key_binding_commitment: [u8; 32],
    pub key_generation: u64,
    pub message_id: [u8; 32],
    pub target_seat_id: [u8; 32],
    pub reply_to: Option<[u8; 32]>,
}

/// A human-authored room message that may reach actors only through their
/// independently authorized all-message subscriptions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanRoomWideHeaderV1 {
    pub chain_id: u64,
    pub room_id: [u8; 32],
    pub seat_id: [u8; 32],
    pub key_binding_commitment: [u8; 32],
    pub key_generation: u64,
    pub message_id: [u8; 32],
    pub reply_to: Option<[u8; 32]>,
}

pub fn human_room_wide_header_v1(message: &HumanRoomWideHeaderV1) -> Result<Vec<u8>> {
    if message.chain_id == 0 || message.key_generation == 0 {
        return Err(Error::Schema);
    }
    for value in [
        &message.room_id,
        &message.seat_id,
        &message.key_binding_commitment,
        &message.message_id,
    ] {
        nonzero_32(value)?;
    }
    let reply_to = message
        .reply_to
        .map(|id| Value::Text(hex32(&id)))
        .unwrap_or(Value::Null);
    canonical::encode(Value::Map(vec![
        (Value::Text("v".into()), Value::Integer(3.into())),
        (
            Value::Text("message_id".into()),
            Value::Text(hex32(&message.message_id)),
        ),
        (
            Value::Text("chain_id".into()),
            Value::Integer(message.chain_id.into()),
        ),
        (
            Value::Text("room".into()),
            Value::Text(hex32(&message.room_id)),
        ),
        (
            Value::Text("seat".into()),
            Value::Text(hex32(&message.seat_id)),
        ),
        (Value::Text("role".into()), Value::Text("human".into())),
        (Value::Text("via".into()), Value::Null),
        (Value::Text("via_sender".into()), Value::Null),
        (Value::Text("class".into()), Value::Text("message".into())),
        (Value::Text("reply_to".into()), reply_to),
        (Value::Text("mentions".into()), Value::Array(vec![])),
        (
            Value::Text("wake_hint".into()),
            Value::Text("normal".into()),
        ),
        (
            Value::Text("gen".into()),
            Value::Integer(message.key_generation.into()),
        ),
        (
            Value::Text("cert".into()),
            Value::Text(hex32(&message.key_binding_commitment)),
        ),
        (
            Value::Text("nonce".into()),
            Value::Text("AAAAAAAAAAAAAAAA".into()),
        ),
    ]))
}

pub fn seal_human_room_wide_message_v1(
    message: &HumanRoomWideHeaderV1,
    generation_secret: &[u8; 32],
    plaintext: &[u8],
    signing_seed: &[u8; 32],
    expected_record_signing_key: &[u8; 32],
) -> Result<Vec<u8>> {
    if SigningKey::from_bytes(signing_seed)
        .verifying_key()
        .to_bytes()
        != *expected_record_signing_key
    {
        return Err(Error::Authority);
    }
    envelope::seal(
        &human_room_wide_header_v1(message)?,
        generation_secret,
        plaintext,
        signing_seed,
    )
}

pub fn human_focused_header_v1(message: &HumanFocusedHeaderV1) -> Result<Vec<u8>> {
    if message.chain_id == 0 || message.key_generation == 0 {
        return Err(Error::Schema);
    }
    for value in [
        &message.room_id,
        &message.seat_id,
        &message.key_binding_commitment,
        &message.message_id,
        &message.target_seat_id,
    ] {
        nonzero_32(value)?;
    }
    if message.seat_id == message.target_seat_id {
        return Err(Error::Scope);
    }
    let reply_to = message
        .reply_to
        .map(|id| Value::Text(hex32(&id)))
        .unwrap_or(Value::Null);
    canonical::encode(Value::Map(vec![
        (Value::Text("v".into()), Value::Integer(3.into())),
        (
            Value::Text("message_id".into()),
            Value::Text(hex32(&message.message_id)),
        ),
        (
            Value::Text("chain_id".into()),
            Value::Integer(message.chain_id.into()),
        ),
        (
            Value::Text("room".into()),
            Value::Text(hex32(&message.room_id)),
        ),
        (
            Value::Text("seat".into()),
            Value::Text(hex32(&message.seat_id)),
        ),
        (Value::Text("role".into()), Value::Text("human".into())),
        (Value::Text("via".into()), Value::Null),
        (Value::Text("via_sender".into()), Value::Null),
        (Value::Text("class".into()), Value::Text("message".into())),
        (Value::Text("reply_to".into()), reply_to),
        (
            Value::Text("mentions".into()),
            Value::Array(vec![Value::Text(hex32(&message.target_seat_id))]),
        ),
        (
            Value::Text("wake_hint".into()),
            Value::Text("normal".into()),
        ),
        (
            Value::Text("gen".into()),
            Value::Integer(message.key_generation.into()),
        ),
        (
            Value::Text("cert".into()),
            Value::Text(hex32(&message.key_binding_commitment)),
        ),
        (
            Value::Text("nonce".into()),
            Value::Text("AAAAAAAAAAAAAAAA".into()),
        ),
    ]))
}

pub fn seal_human_focused_message_v1(
    message: &HumanFocusedHeaderV1,
    generation_secret: &[u8; 32],
    plaintext: &[u8],
    signing_seed: &[u8; 32],
    expected_record_signing_key: &[u8; 32],
) -> Result<Vec<u8>> {
    if SigningKey::from_bytes(signing_seed)
        .verifying_key()
        .to_bytes()
        != *expected_record_signing_key
    {
        return Err(Error::Authority);
    }
    envelope::seal(
        &human_focused_header_v1(message)?,
        generation_secret,
        plaintext,
        signing_seed,
    )
}

struct SealedRecord {
    header: Vec<u8>,
    body: String,
    signature: Vec<u8>,
}

struct CheckedSourceSeatHeader {
    attribution: Option<GatewayAttributionV1>,
    message_id: [u8; 32],
    reply_to: Option<[u8; 32]>,
    mentions: Vec<[u8; 32]>,
}

fn nonzero_32(value: &[u8; 32]) -> Result<()> {
    if *value == [0; 32] {
        Err(Error::Schema)
    } else {
        Ok(())
    }
}

fn hex32(value: &[u8; 32]) -> String {
    hex::encode(value)
}

fn parse_hex32(value: String) -> Result<[u8; 32]> {
    if value.len() != 64
        || value
            .bytes()
            .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
    {
        return Err(Error::Schema);
    }
    hex::decode(value)
        .map_err(|_| Error::Schema)?
        .try_into()
        .map_err(|_| Error::Schema)
}

fn parse_sealed_record(raw: &[u8]) -> Result<SealedRecord> {
    if raw.len() > MAX_SEALED_RECORD_BYTES {
        return Err(Error::Limit);
    }
    let mut cursor = Cursor::new(raw);
    let value: Value = ciborium::from_reader(&mut cursor).map_err(|_| Error::Encoding)?;
    if cursor.position() != raw.len() as u64 {
        return Err(Error::Encoding);
    }
    let Value::Array(values) = value else {
        return Err(Error::Schema);
    };
    let [Value::Bytes(header), Value::Text(body), Value::Bytes(signature)] = values.as_slice()
    else {
        return Err(Error::Schema);
    };
    if body.len() > envelope::MAX_BODY_BYTES || signature.len() != 64 {
        return Err(Error::Limit);
    }
    canonical::validate(header)?;
    Ok(SealedRecord {
        header: header.clone(),
        body: body.clone(),
        signature: signature.clone(),
    })
}

fn parse_header(header: &[u8]) -> Result<Fields> {
    Fields::new(canonical::decode(header)?, HEADER_FIELDS)
}

fn check_source_seat_record_header(
    header: &[u8],
    expected: &ExpectedSourceSeatRecordV1,
) -> Result<CheckedSourceSeatHeader> {
    if expected.chain_id == 0 || expected.key_generation == 0 {
        return Err(Error::Schema);
    }
    for value in [
        &expected.room_id,
        &expected.source_seat_id,
        &expected.source_key_binding_commitment,
        &expected.target_seat_id,
    ] {
        nonzero_32(value)?;
    }

    validate_source_profile(expected.source_seat_kind, expected.gateway_ref.as_deref())?;
    let expected_role = expected.source_seat_kind.header_role()?;
    let fields = parse_header(header)?;
    let mentions = fields
        .strings("mentions")?
        .into_iter()
        .map(parse_hex32)
        .collect::<Result<Vec<_>>>()?;
    let message_id = parse_hex32(fields.text("message_id")?)?;
    let reply_to = fields
        .nullable_text("reply_to")?
        .map(parse_hex32)
        .transpose()?;
    let expected_room = hex32(&expected.room_id);
    let expected_seat = hex32(&expected.source_seat_id);
    let expected_cert = hex32(&expected.source_key_binding_commitment);

    if fields.uint("v")? != 3
        || fields.uint("chain_id")? != expected.chain_id
        || fields.text("room")? != expected_room
        || fields.text("seat")? != expected_seat
        || fields.text("role")? != expected_role
        || fields.text("class")? != "message"
        || !matches!(fields.text("wake_hint")?.as_str(), "normal" | "urgent")
        || fields.uint("gen")? != expected.key_generation
        || fields.text("cert")? != expected_cert
        || !mentions.contains(&expected.target_seat_id)
    {
        return Err(Error::Scope);
    }
    Ok(CheckedSourceSeatHeader {
        attribution: check_attribution(
            &fields,
            expected.source_seat_kind,
            expected.gateway_ref.as_deref(),
        )?,
        message_id,
        reply_to,
        mentions,
    })
}

/// Authenticate the public route fields without opening the ciphertext.
/// The expected source fields and key must come from finalized seat authority.
pub fn authenticate_source_seat_header_v1(
    sealed_record: &[u8],
    expected: &ExpectedSourceSeatRecordV1,
    source_record_signing_key: &[u8; 32],
) -> Result<AuthenticatedSourceSeatHeaderV1> {
    validate_source_profile(expected.source_seat_kind, expected.gateway_ref.as_deref())?;
    nonzero_32(source_record_signing_key)?;
    let sealed = parse_sealed_record(sealed_record)?;
    envelope::verify_record(
        &sealed.header,
        &sealed.body,
        source_record_signing_key,
        &sealed.signature,
    )?;
    let checked = check_source_seat_record_header(&sealed.header, expected)?;
    Ok(AuthenticatedSourceSeatHeaderV1 {
        attribution: checked.attribution,
        message_id: checked.message_id,
        reply_to: checked.reply_to,
        mentions: checked.mentions,
    })
}

/// Authenticate a room-wide record with no explicit actor mentions. An inbox
/// consumer must separately verify its own historical subscription.
pub fn authenticate_room_wide_source_seat_header_v1(
    sealed_record: &[u8],
    expected: &ExpectedRoomWideSourceSeatRecordV1,
    source_record_signing_key: &[u8; 32],
) -> Result<AuthenticatedSourceSeatHeaderV1> {
    validate_source_profile(expected.source_seat_kind, expected.gateway_ref.as_deref())?;
    let expected_role = expected.source_seat_kind.header_role()?;
    nonzero_32(source_record_signing_key)?;
    if expected.chain_id == 0 || expected.key_generation == 0 {
        return Err(Error::Schema);
    }
    for value in [
        &expected.room_id,
        &expected.source_seat_id,
        &expected.source_key_binding_commitment,
    ] {
        nonzero_32(value)?;
    }
    let sealed = parse_sealed_record(sealed_record)?;
    envelope::verify_record(
        &sealed.header,
        &sealed.body,
        source_record_signing_key,
        &sealed.signature,
    )?;
    let fields = parse_header(&sealed.header)?;
    let mentions = fields.strings("mentions")?;
    if fields.uint("v")? != 3
        || fields.uint("chain_id")? != expected.chain_id
        || fields.text("room")? != hex32(&expected.room_id)
        || fields.text("seat")? != hex32(&expected.source_seat_id)
        || fields.text("role")? != expected_role
        || fields.text("class")? != "message"
        || fields.text("wake_hint")? != "normal"
        || fields.uint("gen")? != expected.key_generation
        || fields.text("cert")? != hex32(&expected.source_key_binding_commitment)
        || !mentions.is_empty()
    {
        return Err(Error::Scope);
    }
    Ok(AuthenticatedSourceSeatHeaderV1 {
        attribution: check_attribution(
            &fields,
            expected.source_seat_kind,
            expected.gateway_ref.as_deref(),
        )?,
        message_id: parse_hex32(fields.text("message_id")?)?,
        reply_to: fields
            .nullable_text("reply_to")?
            .map(parse_hex32)
            .transpose()?,
        mentions: Vec::new(),
    })
}

pub fn open_room_wide_source_seat_record_v1(
    sealed_record: &[u8],
    expected: &ExpectedRoomWideSourceSeatRecordV1,
    source_record_signing_key: &[u8; 32],
    generation_secret: &[u8; 32],
) -> Result<OpenedSourceSeatRecordV1> {
    let header = authenticate_room_wide_source_seat_header_v1(
        sealed_record,
        expected,
        source_record_signing_key,
    )?;
    let sealed = parse_sealed_record(sealed_record)?;
    let plaintext = envelope::open(
        &sealed.header,
        &sealed.body,
        source_record_signing_key,
        &sealed.signature,
        generation_secret,
    )?;
    let (paired_salt, plaintext) = open_source_body(&header.message_id, plaintext)?;
    Ok(OpenedSourceSeatRecordV1 {
        attribution: header.attribution,
        message_id: header.message_id,
        reply_to: header.reply_to,
        mentions: header.mentions,
        plaintext,
        paired_salt,
    })
}

fn open_source_body(message_id: &[u8; 32], body: Vec<u8>) -> Result<(Option<[u8; 32]>, Vec<u8>)> {
    if crate::paired_message_id::is_paired_message_id_v2(message_id) {
        let (salt, plaintext) = crate::paired_message_id::open_paired_body_v2(message_id, &body)
            .ok_or(Error::Decrypt)?;
        Ok((Some(salt), plaintext.to_vec()))
    } else if message_id.starts_with(b"cwp1") {
        Err(Error::Decrypt)
    } else {
        Ok((None, body))
    }
}

/// Verify the source seat signature, principal-kind role and every
/// proof-derived identity coordinate before releasing plaintext to the caller.
pub fn open_source_seat_record_v1(
    sealed_record: &[u8],
    expected: &ExpectedSourceSeatRecordV1,
    source_record_signing_key: &[u8; 32],
    generation_secret: &[u8; 32],
) -> Result<OpenedSourceSeatRecordV1> {
    // Refuse a missing or misapplied Gateway authority reference before
    // parsing or opening caller-controlled ciphertext.
    validate_source_profile(expected.source_seat_kind, expected.gateway_ref.as_deref())?;
    nonzero_32(source_record_signing_key)?;
    let sealed = parse_sealed_record(sealed_record)?;
    envelope::verify_record(
        &sealed.header,
        &sealed.body,
        source_record_signing_key,
        &sealed.signature,
    )?;
    let checked = check_source_seat_record_header(&sealed.header, expected)?;
    let plaintext = envelope::open(
        &sealed.header,
        &sealed.body,
        source_record_signing_key,
        &sealed.signature,
        generation_secret,
    )?;
    let (paired_salt, plaintext) = open_source_body(&checked.message_id, plaintext)?;
    Ok(OpenedSourceSeatRecordV1 {
        attribution: checked.attribution,
        message_id: checked.message_id,
        reply_to: checked.reply_to,
        mentions: checked.mentions,
        plaintext,
        paired_salt,
    })
}

/// Read the signed public message id without decrypting the room body.
///
/// Recovery code uses this to find a previously appended sealed reply after an
/// ambiguous transport result. The id is returned only after the record
/// signature verifies under the finalized seat key supplied by the caller.
pub fn authenticated_record_message_id_v1(
    sealed_record: &[u8],
    record_signing_key: &[u8; 32],
) -> Result<[u8; 32]> {
    nonzero_32(record_signing_key)?;
    let sealed = parse_sealed_record(sealed_record)?;
    envelope::verify_record(
        &sealed.header,
        &sealed.body,
        record_signing_key,
        &sealed.signature,
    )?;
    parse_hex32(parse_header(&sealed.header)?.text("message_id")?)
}

/// Build the one canonical direct actor-reply header. Native replies carry no
/// gateway attribution and do not wake another seat implicitly.
pub fn actor_reply_header_v1(reply: &ActorReplyHeaderV1) -> Result<Vec<u8>> {
    if reply.chain_id == 0 || reply.key_generation == 0 {
        return Err(Error::Schema);
    }
    for value in [
        &reply.room_id,
        &reply.seat_id,
        &reply.key_binding_commitment,
        &reply.message_id,
        &reply.reply_to,
    ] {
        nonzero_32(value)?;
    }
    canonical::encode(Value::Map(vec![
        (Value::Text("v".into()), Value::Integer(3.into())),
        (
            Value::Text("message_id".into()),
            Value::Text(hex32(&reply.message_id)),
        ),
        (
            Value::Text("chain_id".into()),
            Value::Integer(reply.chain_id.into()),
        ),
        (
            Value::Text("room".into()),
            Value::Text(hex32(&reply.room_id)),
        ),
        (
            Value::Text("seat".into()),
            Value::Text(hex32(&reply.seat_id)),
        ),
        (Value::Text("role".into()), Value::Text("actor".into())),
        (Value::Text("via".into()), Value::Null),
        (Value::Text("via_sender".into()), Value::Null),
        (Value::Text("class".into()), Value::Text("message".into())),
        (
            Value::Text("reply_to".into()),
            Value::Text(hex32(&reply.reply_to)),
        ),
        (Value::Text("mentions".into()), Value::Array(Vec::new())),
        (Value::Text("wake_hint".into()), Value::Text("none".into())),
        (
            Value::Text("gen".into()),
            Value::Integer(reply.key_generation.into()),
        ),
        (
            Value::Text("cert".into()),
            Value::Text(hex32(&reply.key_binding_commitment)),
        ),
        (
            Value::Text("nonce".into()),
            Value::Text("AAAAAAAAAAAAAAAA".into()),
        ),
    ]))
}

/// Seal a canonical direct actor reply and require the signing seed to match
/// the finalized seat record key supplied by the caller.
pub fn seal_actor_reply_v1(
    reply: &ActorReplyHeaderV1,
    generation_secret: &[u8; 32],
    plaintext: &[u8],
    signing_seed: &[u8; 32],
    expected_record_signing_key: &[u8; 32],
) -> Result<Vec<u8>> {
    let actual = SigningKey::from_bytes(signing_seed)
        .verifying_key()
        .to_bytes();
    if actual != *expected_record_signing_key {
        return Err(Error::Authority);
    }
    envelope::seal(
        &actor_reply_header_v1(reply)?,
        generation_secret,
        plaintext,
        signing_seed,
    )
}

/// Validate an actor reply against its exact protocol-derived identifiers and
/// signing key, then decrypt it. This is also a caller-seam check for retries.
pub fn open_actor_reply_v1(
    sealed_record: &[u8],
    expected: &ActorReplyHeaderV1,
    record_signing_key: &[u8; 32],
    generation_secret: &[u8; 32],
) -> Result<Vec<u8>> {
    let sealed = parse_sealed_record(sealed_record)?;
    envelope::verify_record(
        &sealed.header,
        &sealed.body,
        record_signing_key,
        &sealed.signature,
    )?;
    let expected_header = actor_reply_header_v1(expected)?;
    let actual = parse_header(&sealed.header)?;
    let canonical = parse_header(&expected_header)?;
    for key in HEADER_FIELDS.iter().copied().filter(|key| *key != "nonce") {
        if actual.get(key)? != canonical.get(key)? {
            return Err(Error::Scope);
        }
    }
    envelope::open(
        &sealed.header,
        &sealed.body,
        record_signing_key,
        &sealed.signature,
        generation_secret,
    )
}

#[cfg(test)]
mod focused_message_tests {
    use super::*;

    #[test]
    fn focused_human_record_is_sealed_for_one_native_target() {
        let signing_seed = [0x41; 32];
        let record_key = SigningKey::from_bytes(&signing_seed)
            .verifying_key()
            .to_bytes();
        let header = HumanFocusedHeaderV1 {
            chain_id: 7,
            room_id: [0x42; 32],
            seat_id: [0x43; 32],
            key_binding_commitment: [0x44; 32],
            key_generation: 3,
            message_id: [0x45; 32],
            target_seat_id: [0x46; 32],
            reply_to: None,
        };
        let secret = [0x47; 32];
        let sealed = seal_human_focused_message_v1(
            &header,
            &secret,
            b"payroll forecast",
            &signing_seed,
            &record_key,
        )
        .unwrap();
        assert_eq!(
            authenticated_record_message_id_v1(&sealed, &record_key).unwrap(),
            header.message_id
        );
        let expected = ExpectedSourceSeatRecordV1 {
            chain_id: header.chain_id,
            room_id: header.room_id,
            source_seat_id: header.seat_id,
            source_seat_kind: SourceSeatKindV1::Human,
            gateway_ref: None,
            source_key_binding_commitment: header.key_binding_commitment,
            key_generation: header.key_generation,
            target_seat_id: header.target_seat_id,
        };
        let authenticated =
            authenticate_source_seat_header_v1(&sealed, &expected, &record_key).unwrap();
        assert_eq!(authenticated.message_id, header.message_id);
        assert_eq!(authenticated.mentions, vec![header.target_seat_id]);
        let opened = open_source_seat_record_v1(&sealed, &expected, &record_key, &secret).unwrap();
        assert_eq!(opened.plaintext, b"payroll forecast");
        assert_eq!(opened.mentions, vec![header.target_seat_id]);
        let wrong = ExpectedSourceSeatRecordV1 {
            target_seat_id: [0x48; 32],
            ..expected
        };
        assert_eq!(
            open_source_seat_record_v1(&sealed, &wrong, &record_key, &secret),
            Err(Error::Scope)
        );
        assert_eq!(
            seal_human_focused_message_v1(&header, &secret, b"x", &[0x49; 32], &record_key),
            Err(Error::Authority)
        );
    }

    #[test]
    fn room_wide_human_record_has_no_sender_chosen_actor_target() {
        let signing_seed = [0x51; 32];
        let record_key = SigningKey::from_bytes(&signing_seed)
            .verifying_key()
            .to_bytes();
        let header = HumanRoomWideHeaderV1 {
            chain_id: 7,
            room_id: [0x52; 32],
            seat_id: [0x53; 32],
            key_binding_commitment: [0x54; 32],
            key_generation: 3,
            message_id: [0x55; 32],
            reply_to: None,
        };
        let secret = [0x56; 32];
        let sealed = seal_human_room_wide_message_v1(
            &header,
            &secret,
            b"ordinary room message",
            &signing_seed,
            &record_key,
        )
        .unwrap();
        let expected = ExpectedRoomWideSourceSeatRecordV1 {
            chain_id: header.chain_id,
            room_id: header.room_id,
            source_seat_id: header.seat_id,
            source_seat_kind: SourceSeatKindV1::Human,
            gateway_ref: None,
            source_key_binding_commitment: header.key_binding_commitment,
            key_generation: header.key_generation,
        };
        let authenticated =
            authenticate_room_wide_source_seat_header_v1(&sealed, &expected, &record_key).unwrap();
        assert_eq!(authenticated.message_id, header.message_id);
        assert!(authenticated.mentions.is_empty());
        let opened =
            open_room_wide_source_seat_record_v1(&sealed, &expected, &record_key, &secret).unwrap();
        assert_eq!(opened.plaintext, b"ordinary room message");
        assert_eq!(
            authenticate_source_seat_header_v1(
                &sealed,
                &ExpectedSourceSeatRecordV1 {
                    chain_id: header.chain_id,
                    room_id: header.room_id,
                    source_seat_id: header.seat_id,
                    source_seat_kind: SourceSeatKindV1::Human,
                    gateway_ref: None,
                    source_key_binding_commitment: header.key_binding_commitment,
                    key_generation: header.key_generation,
                    target_seat_id: [0x57; 32],
                },
                &record_key,
            ),
            Err(Error::Scope)
        );
        let mut altered = sealed.clone();
        *altered.last_mut().unwrap() ^= 1;
        assert!(
            authenticate_room_wide_source_seat_header_v1(&altered, &expected, &record_key).is_err()
        );
    }
}
