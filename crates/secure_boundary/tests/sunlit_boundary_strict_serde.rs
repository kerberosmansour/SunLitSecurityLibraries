use secure_boundary::serde::StrictDeserialize;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserDto {
    username: String,
}

#[test]
fn test_strict_deserialize_known_field_passes() {
    let json = br#"{"username": "alice"}"#;
    let result = StrictDeserialize::<UserDto>::from_json(json);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().username, "alice");
}

#[test]
fn test_strict_deserialize_unknown_field_fails() {
    // "role" is not a known field — must be rejected
    let json = br#"{"username": "alice", "role": "admin"}"#;
    let result = StrictDeserialize::<UserDto>::from_json(json);
    assert!(result.is_err(), "unknown field 'role' should be rejected");
}

#[test]
fn test_strict_deserialize_null_string_fails() {
    // username is String, null should fail deserialization
    let json = br#"{"username": null}"#;
    let result = StrictDeserialize::<UserDto>::from_json(json);
    assert!(result.is_err(), "null for String field should be rejected");
}

#[test]
fn test_strict_deserialize_missing_field_fails() {
    let json = br#"{}"#;
    let result = StrictDeserialize::<UserDto>::from_json(json);
    assert!(result.is_err(), "missing required field should be rejected");
}
