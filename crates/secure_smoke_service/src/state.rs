//! Application state for the smoke-test microservice.

use std::sync::Arc;

use secure_authz::enforcer::DefaultAuthorizer;
use secure_authz::policy::DefaultPolicyEngine;
use secure_data::keyring::KeyRing;
use secure_data::kms::StaticDevKeyProvider;
use secure_identity::session::InMemorySessionManager;
use secure_identity::token::{TokenValidator, TokenValidatorConfig};
use tokio::sync::RwLock;

use crate::config::SecurityConfig;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    /// JWT token validator (HS256).
    pub token_validator: Arc<TokenValidator>,
    /// Policy-based authorizer.
    pub authorizer: Arc<DefaultAuthorizer<DefaultPolicyEngine>>,
    /// Encryption key provider (dev only).
    pub key_provider: Arc<StaticDevKeyProvider>,
    /// Key lifecycle management.
    pub key_ring: Arc<RwLock<KeyRing>>,
    /// In-memory session manager.
    pub session_manager: Arc<InMemorySessionManager>,
}

impl AppState {
    /// Creates a new `AppState` with development defaults.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy engine fails to initialise.
    pub async fn new(config: &SecurityConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let token_validator = Arc::new(TokenValidator::new(TokenValidatorConfig {
            issuer: config.jwt_issuer.clone(),
            audience: config.jwt_audience.clone(),
            secret: config.jwt_secret.clone(),
        }));

        let engine = DefaultPolicyEngine::new_empty().await?;
        engine.add_policy("admin", "items", "create").await?;
        engine.add_policy("admin", "items", "read").await?;
        engine.add_policy("admin", "items", "write").await?;
        engine.add_policy("admin", "items", "delete").await?;
        engine.add_policy("reader", "items", "read").await?;
        engine.add_policy("admin", "smoke", "read").await?;
        engine.add_policy("reader", "smoke", "read").await?;

        let authorizer = Arc::new(DefaultAuthorizer::new(Arc::new(engine)));
        let key_provider = Arc::new(StaticDevKeyProvider::new());
        let key_ring = Arc::new(RwLock::new(KeyRing::new()));
        let session_manager = Arc::new(InMemorySessionManager::new());

        Ok(Self {
            token_validator,
            authorizer,
            key_provider,
            key_ring,
            session_manager,
        })
    }
}
