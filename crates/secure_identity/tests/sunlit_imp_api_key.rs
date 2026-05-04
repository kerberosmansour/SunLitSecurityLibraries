//! BDD tests for ApiKeyAuthenticator.

use secure_identity::api_key::ApiKeyAuthenticator;
use secure_identity::authenticator::{AuthenticationRequest, Authenticator, TokenKind};
use secure_identity::error::IdentityError;
use security_core::types::ActorId;
use uuid::Uuid;

fn make_authenticator() -> ApiKeyAuthenticator {
    let actor_id = ActorId::from(Uuid::new_v4());
    let api_key = "sunlit-test-api-key-1234567890abcdef";
    ApiKeyAuthenticator::new(api_key.to_string(), actor_id, vec!["api-user".to_string()])
}

// --- Feature: API key authentication ---

#[tokio::test]
async fn scenario_valid_api_key_accepted() {
    // Given: key matches stored key
    let authenticator = make_authenticator();
    let req = AuthenticationRequest {
        token: "sunlit-test-api-key-1234567890abcdef".to_string(),
        token_kind: TokenKind::ApiKey,
    };

    // When: authenticate
    let result = authenticator.authenticate(&req).await;

    // Then: returns identity
    let identity = result.expect("should authenticate");
    assert_eq!(identity.roles, vec!["api-user"]);
}

#[tokio::test]
async fn scenario_invalid_api_key_rejected() {
    // Given: key does not match
    let authenticator = make_authenticator();
    let req = AuthenticationRequest {
        token: "sk-wrong-key-doesntmatch!!!".to_string(),
        token_kind: TokenKind::ApiKey,
    };

    // When: authenticate
    let result = authenticator.authenticate(&req).await;

    // Then: IdentityError::InvalidCredentials
    assert!(matches!(result, Err(IdentityError::InvalidCredentials)));
}

#[tokio::test]
async fn scenario_empty_key_rejected() {
    // Given: empty string
    let authenticator = make_authenticator();
    let req = AuthenticationRequest {
        token: String::new(),
        token_kind: TokenKind::ApiKey,
    };

    // When: authenticate
    let result = authenticator.authenticate(&req).await;

    // Then: IdentityError::InvalidCredentials
    assert!(matches!(result, Err(IdentityError::InvalidCredentials)));
}

#[tokio::test]
async fn scenario_api_key_returns_correct_actor() {
    // Given: authenticator configured with specific actor
    let actor_id =
        ActorId::from(Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("uuid"));
    let authenticator = ApiKeyAuthenticator::new(
        "sunlit-specific-key".to_string(),
        actor_id,
        vec!["admin".to_string(), "reader".to_string()],
    );
    let req = AuthenticationRequest {
        token: "sunlit-specific-key".to_string(),
        token_kind: TokenKind::ApiKey,
    };

    // When: authenticate
    let identity = authenticator.authenticate(&req).await.expect("auth");

    // Then: returns correct actor and roles
    assert_eq!(
        identity.actor_id.as_inner(),
        &Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("uuid")
    );
    assert_eq!(identity.roles, vec!["admin", "reader"]);
}
