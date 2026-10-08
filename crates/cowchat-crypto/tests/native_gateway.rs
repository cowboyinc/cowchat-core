use ciborium::value::Value;
use cowchat_crypto::{canonical, envelope, native_actor::*, Error};
use ed25519_dalek::SigningKey;

fn input(target: bool) -> (GatewayMessageHeaderV1, [u8; 32], [u8; 32], [u8; 32]) {
    let seed = [7; 32];
    let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    (
        GatewayMessageHeaderV1 {
            message: HumanRoomWideHeaderV1 {
                chain_id: 7,
                room_id: [1; 32],
                seat_id: [2; 32],
                key_binding_commitment: [3; 32],
                key_generation: 9,
                message_id: [4; 32],
                reply_to: Some([5; 32]),
            },
            target_seat_id: target.then_some([6; 32]),
            attribution: GatewayAttributionV1 {
                gateway_ref: "telegram:-10012345".into(),
                sender_id: "87654321".into(),
            },
        },
        seed,
        public,
        [8; 32],
    )
}

fn focused(message: &GatewayMessageHeaderV1) -> ExpectedSourceSeatRecordV1 {
    ExpectedSourceSeatRecordV1 {
        chain_id: message.message.chain_id,
        room_id: message.message.room_id,
        source_seat_id: message.message.seat_id,
        source_seat_kind: SourceSeatKindV1::Gateway,
        gateway_ref: Some(message.attribution.gateway_ref.clone()),
        source_key_binding_commitment: message.message.key_binding_commitment,
        key_generation: message.message.key_generation,
        target_seat_id: message.target_seat_id.unwrap(),
    }
}

fn changed_header(message: &GatewayMessageHeaderV1, field: &str, value: Value) -> Vec<u8> {
    let Value::Map(mut fields) =
        ciborium::from_reader(gateway_message_header_v1(message).unwrap().as_slice()).unwrap()
    else {
        panic!()
    };
    fields
        .iter_mut()
        .find(|(key, _)| key.as_text() == Some(field))
        .unwrap()
        .1 = value;
    encode(Value::Map(fields))
}

#[test]
fn focused_gateway_authenticates_its_channel_and_external_sender_before_open() {
    let (message, seed, public, secret) = input(true);
    let sealed =
        seal_gateway_message_v1(&message, &secret, b"@oracle quote", &seed, &public).unwrap();
    let expected = focused(&message);
    let header = authenticate_source_seat_header_v1(&sealed, &expected, &public).unwrap();
    assert_eq!(header.attribution, Some(message.attribution.clone()));
    assert_eq!(header.mentions, vec![[6; 32]]);
    let opened = open_source_seat_record_v1(&sealed, &expected, &public, &secret).unwrap();
    assert_eq!(opened.attribution, header.attribution);
    assert_eq!(opened.plaintext, b"@oracle quote");
    assert_eq!(opened.reply_to, Some([5; 32]));
    assert_eq!(opened.message_id, [4; 32]);
    for field in 0..7 {
        let mut wrong = expected.clone();
        match field {
            0 => wrong.gateway_ref = None,
            1 => wrong.gateway_ref = Some("telegram:-10099999".into()),
            2 => wrong.room_id = [10; 32],
            3 => wrong.source_seat_id = [10; 32],
            4 => wrong.source_key_binding_commitment = [10; 32],
            5 => wrong.key_generation += 1,
            _ => wrong.target_seat_id = [10; 32],
        }
        assert_eq!(
            open_source_seat_record_v1(&sealed, &wrong, &public, &[0; 32]),
            Err(Error::Scope),
            "identity mismatch {field} must precede decryption"
        );
    }
    assert_eq!(
        seal_gateway_message_v1(&message, &secret, b"x", &seed, &[0; 32]),
        Err(Error::Authority)
    );
}

#[test]
fn room_wide_gateway_still_requires_gateway_authority_and_signed_attribution() {
    let (message, seed, public, secret) = input(false);
    let sealed = seal_gateway_message_v1(&message, &secret, b"hello room", &seed, &public).unwrap();
    let mut expected = ExpectedRoomWideSourceSeatRecordV1 {
        chain_id: message.message.chain_id,
        room_id: message.message.room_id,
        source_seat_id: message.message.seat_id,
        source_seat_kind: SourceSeatKindV1::Gateway,
        gateway_ref: Some(message.attribution.gateway_ref.clone()),
        source_key_binding_commitment: message.message.key_binding_commitment,
        key_generation: message.message.key_generation,
    };
    let opened =
        open_room_wide_source_seat_record_v1(&sealed, &expected, &public, &secret).unwrap();
    assert!(opened.mentions.is_empty());
    assert_eq!(opened.attribution, Some(message.attribution));
    expected.gateway_ref = Some("telegram:other".into());
    assert_eq!(
        open_room_wide_source_seat_record_v1(&sealed, &expected, &public, &secret),
        Err(Error::Scope)
    );
    expected.gateway_ref = None;
    expected.source_seat_kind = SourceSeatKindV1::Human;
    assert_eq!(
        open_room_wide_source_seat_record_v1(&sealed, &expected, &public, &secret),
        Err(Error::Scope)
    );
}

#[test]
fn gateway_cannot_claim_human_actor_or_owner_rights_even_with_a_valid_signature() {
    let (message, seed, public, secret) = input(true);
    let expected = focused(&message);
    for role in ["human", "actor", "owner", "builder", "door"] {
        let header = changed_header(&message, "role", Value::Text(role.into()));
        let sealed =
            envelope::seal(&header, &secret, b"signed but unauthorized role", &seed).unwrap();
        assert_eq!(
            open_source_seat_record_v1(&sealed, &expected, &public, &secret),
            Err(Error::Scope)
        );
    }
    for (field, value) in [
        ("via", Value::Null),
        ("via_sender", Value::Null),
        ("via_sender", Value::Text("user\nowner".into())),
        ("via_sender", Value::Text("x".repeat(129))),
    ] {
        // Generic envelope framing also refuses sender-without-via.
        if let Ok(sealed) = envelope::seal(
            &changed_header(&message, field, value),
            &secret,
            b"x",
            &seed,
        ) {
            assert_eq!(
                open_source_seat_record_v1(&sealed, &expected, &public, &secret),
                Err(Error::Scope)
            );
        }
    }
    let direct = HumanFocusedHeaderV1 {
        chain_id: 7,
        room_id: [1; 32],
        seat_id: [2; 32],
        key_binding_commitment: [3; 32],
        key_generation: 9,
        message_id: [4; 32],
        target_seat_id: [6; 32],
        reply_to: None,
    };
    let sealed =
        seal_human_focused_message_v1(&direct, &secret, b"not a door", &seed, &public).unwrap();
    assert_eq!(
        open_source_seat_record_v1(&sealed, &expected, &public, &secret),
        Err(Error::Scope)
    );
    let mut human = expected;
    human.source_seat_kind = SourceSeatKindV1::Human;
    assert_eq!(
        open_source_seat_record_v1(&sealed, &human, &public, &secret),
        Err(Error::Scope),
        "Gateway authority cannot be attached to a Human profile"
    );
}

#[test]
fn unsigned_provenance_changes_and_other_seat_keys_are_refused() {
    let (message, seed, public, secret) = input(true);
    let sealed = seal_gateway_message_v1(&message, &secret, b"x", &seed, &public).unwrap();
    let mut outer: Value = ciborium::from_reader(sealed.as_slice()).unwrap();
    let Value::Array(ref mut tuple) = outer else {
        panic!()
    };
    let Value::Bytes(header) = &tuple[0] else {
        panic!()
    };
    let Value::Map(mut fields) = ciborium::from_reader(header.as_slice()).unwrap() else {
        panic!()
    };
    fields
        .iter_mut()
        .find(|(key, _)| key.as_text() == Some("via_sender"))
        .unwrap()
        .1 = Value::Text("999".into());
    tuple[0] = Value::Bytes(encode(Value::Map(fields)));
    let mut changed = Vec::new();
    ciborium::into_writer(&outer, &mut changed).unwrap();
    assert_eq!(
        authenticate_source_seat_header_v1(&changed, &focused(&message), &public),
        Err(Error::Signature)
    );
    let other = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
    assert_eq!(
        open_source_seat_record_v1(&sealed, &focused(&message), &other, &secret),
        Err(Error::Signature)
    );
}

#[test]
fn gateway_identifiers_are_bounded_opaque_ids_not_display_text() {
    for value in ["", "a b", "a\nb", "a\0b", "用户", &"x".repeat(129)] {
        assert_eq!(validate_gateway_identifier_v1(value), Err(Error::Scope));
    }
    for value in [
        "telegram:-10012345",
        "user_1",
        "provider/channel+thread",
        &"x".repeat(128),
    ] {
        validate_gateway_identifier_v1(value).unwrap();
    }
}

fn encode(value: Value) -> Vec<u8> {
    let mut raw = Vec::new();
    ciborium::into_writer(&value, &mut raw).unwrap();
    canonical::canonicalize(&raw).unwrap()
}
