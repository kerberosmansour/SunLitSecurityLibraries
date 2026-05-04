//! BDD tests for DevAuthenticator.

#[cfg(feature = "dev")]
mod dev_tests {
    use secure_identity::{
        authenticator::{AuthenticationRequest, Authenticator, TokenKind},
        dev::DevAuthenticator,
    };
    use security_core::types::ActorId;
    use uuid::Uuid;

    #[tokio::test]
    async fn scenario_dev_authenticator_accepts_any_credentials() {
        let actor_id = ActorId::from(Uuid::new_v4());
        let dev = DevAuthenticator::new(actor_id.clone(), None, vec!["admin".to_string()]);
        let req = AuthenticationRequest {
            token: "any-token-value".to_string(),
            token_kind: TokenKind::BearerJwt,
        };
        let result = dev.authenticate(&req).await;
        assert!(result.is_ok());
        let identity = result.unwrap();
        assert_eq!(identity.actor_id.as_inner(), actor_id.as_inner());
        assert_eq!(identity.roles, vec!["admin"]);
    }

    #[tokio::test]
    async fn scenario_dev_authenticator_emits_warning() {
        let actor_id = ActorId::from(Uuid::new_v4());
        let _dev = DevAuthenticator::new(actor_id, None, vec![]);
    }
}

#[cfg(not(feature = "dev"))]
#[test]
fn dev_authenticator_not_available_without_feature() {
    // compile-time guard
}
