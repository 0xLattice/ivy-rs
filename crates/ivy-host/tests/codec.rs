use ivy_host::codec::{decode, encode, Kind, Value};
fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}
#[test]
fn all_swift_event_and_effect_vectors_roundtrip_with_strict_lengths() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/swift-3.1.1-events.json")).unwrap();
    for (group, kind) in [("events", Kind::Event), ("effects", Kind::Effect)] {
        for vector in vectors[group].as_array().unwrap() {
            let name = vector["description"].as_str().unwrap();
            let bytes = hex(vector["hex"].as_str().unwrap());
            let value = decode(kind, &bytes).unwrap_or_else(|| panic!("cannot decode {name}"));
            assert_eq!(encode(kind, &value).unwrap(), bytes, "{name}");
            for end in 0..bytes.len() {
                assert!(
                    decode(kind, &bytes[..end]).is_none(),
                    "accepted truncation {end} of {name}"
                );
            }
            let mut trailing = bytes;
            trailing.push(0);
            assert!(
                decode(kind, &trailing).is_none(),
                "accepted trailing bytes {name}"
            );
        }
    }
}
#[test]
fn config_defaults_duration_and_invalid_structures() {
    let mut bytes = vec![2];
    bytes.extend([1; 32]);
    bytes.extend([0; 18]);
    let config = decode(Kind::Config, &bytes).unwrap();
    assert_eq!(encode(Kind::Config, &config), Some(bytes));
    let duration = |seconds, attoseconds| Value::Tagged {
        tag: 13,
        fields: vec![Value::Fields(vec![
            Value::Signed(seconds),
            Value::Signed(attoseconds),
        ])],
    };
    for (s, a) in [(1, -1), (-1, 1), (0, 1_000_000_000_000_000_000)] {
        assert!(encode(Kind::Effect, &duration(s, a)).is_none());
    }
    assert!(encode(Kind::Effect, &duration(-1, -1)).is_some());
    assert!(decode(Kind::Event, &[2, 13, 2]).is_none());
    assert!(decode(Kind::Event, &[2, 255]).is_none());
    assert!(decode(Kind::Effects, &[2, 255, 255, 255, 255]).is_none());
}
