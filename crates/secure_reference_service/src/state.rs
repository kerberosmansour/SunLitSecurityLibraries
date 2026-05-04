//! Shared application state.
//!
//! [`AppState`] is cloned per request. It holds the in-memory item store,
//! the authorizer, and the dev key provider.

use std::collections::HashMap;
use std::sync::Arc;

use secure_authz::enforcer::DefaultAuthorizer;
use secure_authz::policy::DefaultPolicyEngine;
use secure_data::keyring::KeyRing;
use secure_data::kms::StaticDevKeyProvider;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::dto::ItemResponse;

/// In-memory item store (keyed by item UUID).
pub type ItemStore = Arc<RwLock<HashMap<Uuid, ItemResponse>>>;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    /// In-memory item storage.
    pub items: ItemStore,
    /// Authorization enforcer.
    pub authorizer: Arc<DefaultAuthorizer<DefaultPolicyEngine>>,
    /// Dev key provider for envelope encryption demonstrations.
    pub key_provider: Arc<StaticDevKeyProvider>,
    /// Key ring for lifecycle management demonstrations.
    pub key_ring: Arc<RwLock<KeyRing>>,
}

impl AppState {
    /// Creates a new `AppState` with a pre-configured in-memory authorizer.
    ///
    /// The policy engine is initialised with a single RBAC rule:
    /// - role `admin` may perform `create`/`read`/`write`/`delete` on `items`.
    /// - role `reader` may perform `read` on `items`.
    ///
    /// # Panics
    /// Panics if the policy engine fails to initialise (should never happen in dev).
    pub async fn new() -> Self {
        let engine = DefaultPolicyEngine::new_empty()
            .await
            .expect("policy engine init");
        // Add RBAC policies
        engine
            .add_policy("admin", "items", "create")
            .await
            .expect("policy");
        engine
            .add_policy("admin", "items", "read")
            .await
            .expect("policy");
        engine
            .add_policy("admin", "items", "write")
            .await
            .expect("policy");
        engine
            .add_policy("admin", "items", "delete")
            .await
            .expect("policy");
        engine
            .add_policy("reader", "items", "read")
            .await
            .expect("policy");

        let authorizer = Arc::new(DefaultAuthorizer::new(Arc::new(engine)));
        let key_provider = Arc::new(StaticDevKeyProvider::new());

        let mut key_ring = KeyRing::new();
        key_ring.add_key("default".to_string(), "v1".to_string());

        Self {
            items: Arc::new(RwLock::new(HashMap::new())),
            authorizer,
            key_provider,
            key_ring: Arc::new(RwLock::new(key_ring)),
        }
    }
}
