use ivy_core::{
    ContentEntry, Message, Volume, VolumeReceiveError, VolumeReceiver, DEFAULT_MAX_FRAME_SIZE,
};

#[test]
fn every_current_tag_matches_swift_and_rejects_truncation_and_trailing_data() {
    let expected_tags = [
        0, 1, 5, 6, 27, 28, 29, 30, 40, 41, 42, 49, 58, 60, 61, 62, 63, 64, 65,
    ];
    let fixtures: Vec<_> = include_str!("fixtures/swift-3.1.1-messages.hex")
        .lines()
        .collect();
    assert_eq!(fixtures.len(), expected_tags.len());
    for (line, tag) in fixtures.into_iter().zip(expected_tags) {
        let bytes: Vec<_> = (0..line.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&line[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(bytes[0], tag);
        let message = Message::from_bytes(&bytes, DEFAULT_MAX_FRAME_SIZE).unwrap();
        assert_eq!(message.encode(DEFAULT_MAX_FRAME_SIZE).unwrap(), bytes);
        for end in 0..bytes.len() {
            assert!(
                Message::from_bytes(&bytes[..end], DEFAULT_MAX_FRAME_SIZE).is_none(),
                "tag {tag} length {end}"
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Message::from_bytes(&trailing, DEFAULT_MAX_FRAME_SIZE).is_none());
        assert!(Message::from_bytes(&bytes, bytes.len() as u32 - 1).is_none());
    }
}
fn volume(root: &str) -> Volume {
    Volume {
        root_cid: root.into(),
        entries: vec![ContentEntry {
            cid: root.into(),
            data: vec![0xaa; 400],
        }],
    }
}
fn receiver(bundle: bool, archive: usize, total: usize) -> VolumeReceiver {
    VolumeReceiver::new(7, "root".into(), bundle, archive, 100, total, 256, false).unwrap()
}
#[test]
fn complete_volume_and_bundle_use_bounded_ordered_chunks() {
    let root = volume("root");
    let child = volume("child");
    let mut rx = receiver(true, 1024, 2048);
    for volume in [&root, &child] {
        for chunk in volume.chunks(7, 256, false).unwrap() {
            rx.receive(&chunk).unwrap();
        }
    }
    rx.receive(&Message::VolumeBundleEnd { request_id: 7 })
        .unwrap();
    let result = rx.finish();
    assert!(result.ended);
    assert!(!result.no_bundle);
    assert_eq!(result.volumes, [root, child]);
    let mut empty = receiver(true, 1024, 2048);
    empty
        .receive(&Message::VolumeBundleEnd { request_id: 7 })
        .unwrap();
    assert!(empty.finish().no_bundle);
}
#[test]
fn archive_encoding_is_canonical_and_requires_root() {
    let mut v = volume("z");
    v.entries.push(ContentEntry {
        cid: "a".into(),
        data: vec![],
    });
    let bytes = v.encode().unwrap();
    let decoded = Volume::decode(&bytes, "z", 2).unwrap();
    assert_eq!(decoded.entries[0].cid, "a");
    assert!(Volume::decode(&bytes, "absent", 2).is_none());
    assert!(Volume::decode(&bytes, "z", 1).is_none());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(Volume::decode(&trailing, "z", 2).is_none());
    v.entries.push(v.entries[0].clone());
    assert!(v.encode().is_none());
}
#[test]
fn protocol_failures_are_distinct_from_consumer_limits() {
    let chunks = volume("root").chunks(7, 256, false).unwrap();
    assert_eq!(
        receiver(false, 10, 1024).receive(&chunks[0]),
        Err(VolumeReceiveError::CallerBoundaryExceeded)
    );
    assert_eq!(
        receiver(false, 1024, 10).receive(&chunks[0]),
        Err(VolumeReceiveError::LocalCapacityUnavailable)
    );
    let mut rx = receiver(false, 1024, 1024);
    assert_eq!(
        rx.receive(&chunks[1]),
        Err(VolumeReceiveError::ProtocolViolation)
    );
    assert_eq!(
        rx.receive(&chunks[0]),
        Err(VolumeReceiveError::AlreadyEnded)
    );
    let mut rx = receiver(true, 1024, 2048);
    rx.receive(&chunks[0]).unwrap();
    assert_eq!(
        rx.receive(&Message::VolumeBundleEnd { request_id: 7 }),
        Err(VolumeReceiveError::ProtocolViolation)
    );
    let mut rx = receiver(true, 1024, 2048);
    for c in &chunks {
        rx.receive(c).unwrap();
    }
    assert_eq!(
        rx.receive(&chunks[0]),
        Err(VolumeReceiveError::ProtocolViolation)
    );
}
#[test]
fn wrong_root_inconsistent_metadata_and_excess_bytes_fail() {
    let mut chunks = volume("root").chunks(7, 256, false).unwrap();
    let mut rx = receiver(false, 1024, 1024);
    rx.receive(&chunks[0]).unwrap();
    if let Message::VolumeChunk { total_bytes, .. } = &mut chunks[1] {
        *total_bytes += 1;
    }
    assert_eq!(
        rx.receive(&chunks[1]),
        Err(VolumeReceiveError::ProtocolViolation)
    );
    let wrong = volume("wrong").chunks(7, 256, false).unwrap();
    assert_eq!(
        receiver(false, 1024, 1024).receive(&wrong[0]),
        Err(VolumeReceiveError::ProtocolViolation)
    );
    let mut one = volume("root").chunks(7, 1024, false).unwrap();
    if let Message::VolumeChunk { total_bytes, .. } = &mut one[0] {
        *total_bytes -= 1;
    }
    let mut rx =
        VolumeReceiver::new(7, "root".into(), false, 1024, 100, 1024, 1024, false).unwrap();
    assert_eq!(
        rx.receive(&one[0]),
        Err(VolumeReceiveError::ProtocolViolation)
    );
}
#[test]
fn relayed_chunk_budget_accounts_for_both_authenticated_envelopes() {
    assert_eq!(
        Message::volume_chunk_data_budget("root", 1024, false),
        Some(878)
    );
    assert_eq!(
        Message::volume_chunk_data_budget("root", 1024, true),
        Some(728)
    );
    assert_eq!(Message::volume_chunk_data_budget("root", 100, true), None);
}

#[test]
fn relay_endpoint_sessions_are_bound_to_route_and_carrier_cannot_rebind() {
    use ivy_core::{Config, Initiator, Responder};
    use rand_core::OsRng;
    let a = Config::new(ed25519_dalek::SigningKey::from_bytes(&[1; 32]));
    let b = Config::new(ed25519_dalek::SigningKey::from_bytes(&[2; 32]));
    let route = [42; 32];
    let (initiator, hello) =
        Initiator::start_on_route(&a, b.peer_key(), route, &mut OsRng).unwrap();
    assert!(Responder::new(&b)
        .receive(&hello, |_| true, &mut OsRng)
        .is_err());
    assert!(Responder::on_route(&b, [43; 32])
        .receive(&hello, |_| true, &mut OsRng)
        .is_err());
    let (waiting, reply) = Responder::on_route(&b, route)
        .receive(&hello, |_| true, &mut OsRng)
        .unwrap();
    let (mut sender, finish) = initiator.receive(&reply).unwrap();
    let mut receiver = waiting.receive(&finish).unwrap();
    let message = Message::PeerMessage {
        topic: "relayed".into(),
        payload: vec![1, 2, 3],
    };
    let record = sender.seal(&message).unwrap();
    assert_eq!(receiver.open(&record), Ok(Some(message)));
}
