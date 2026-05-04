use secure_boundary::dto::SecureDto;
use serde::Deserialize;

/// DTO that explicitly declares which fields it accepts, preventing mass-assignment.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateUserDto {
    username: String,
    email: String,
}

impl SecureDto for CreateUserDto {}

#[test]
fn test_secure_dto_marker_is_implemented() {
    fn accepts_dto<T: SecureDto>() {}
    accepts_dto::<CreateUserDto>();
}

#[test]
fn test_dto_rejects_unknown_fields() {
    // Attempt to assign "role" which is not declared in the DTO
    let json = r#"{"username": "alice", "email": "alice@example.com", "role": "admin"}"#;
    let result: Result<CreateUserDto, _> = serde_json::from_str(json);
    assert!(
        result.is_err(),
        "mass assignment via unknown field 'role' should be rejected"
    );
}

#[test]
fn test_dto_accepts_known_fields() {
    let json = r#"{"username": "alice", "email": "alice@example.com"}"#;
    let result: Result<CreateUserDto, _> = serde_json::from_str(json);
    assert!(result.is_ok());
    let dto = result.unwrap();
    assert_eq!(dto.username, "alice");
    assert_eq!(dto.email, "alice@example.com");
}

#[test]
fn test_dto_rejects_extra_sensitive_fields() {
    // Attempt to assign "password_hash" — not in DTO
    let json = r#"{"username": "alice", "email": "alice@example.com", "password_hash": "evil"}"#;
    let result: Result<CreateUserDto, _> = serde_json::from_str(json);
    assert!(result.is_err(), "sensitive extra field should be rejected");
}
