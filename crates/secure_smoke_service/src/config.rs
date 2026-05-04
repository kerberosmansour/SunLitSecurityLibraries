//! Service configuration for the smoke-test microservice.

/// Security configuration for the smoke service.
#[derive(Clone)]
pub struct SecurityConfig {
    /// HMAC-SHA256 secret for JWT validation.
    pub jwt_secret: Vec<u8>,
    /// Expected JWT issuer.
    pub jwt_issuer: String,
    /// Expected JWT audience.
    pub jwt_audience: String,
}

impl SecurityConfig {
    /// Development configuration with a fixed secret.
    ///
    /// # Safety
    ///
    /// This is **not** for production. The secret is hard-coded for testing only.
    #[must_use]
    pub fn dev() -> Self {
        Self {
            jwt_secret: b"smoke-test-secret-key-min-32-bytes!!".to_vec(),
            jwt_issuer: "smoke-test-issuer".to_string(),
            jwt_audience: "smoke-test-audience".to_string(),
        }
    }
}
