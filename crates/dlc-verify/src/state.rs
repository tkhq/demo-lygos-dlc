//! Shared server state.

use crate::client::HttpClient;
use qos_p256::P256Pair;
use std::sync::Arc;

/// Shared application state.
///
/// The quorum key is loaded at startup to confirm QOS provisioned it, but this app signs
/// only with the ephemeral key, which is the one sealed to this binary at boot and
/// therefore the one an app proof should be attributable to.
#[derive(Clone)]
pub struct AppState {
    pub(crate) ephemeral_key: Arc<P256Pair>,
    pub(crate) http_client: HttpClient,
}

impl AppState {
    /// Create a new application state value.
    ///
    /// # Errors
    ///
    /// Returns an error if the outbound HTTP client cannot be built.
    pub fn new(ephemeral_key: P256Pair) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            ephemeral_key: Arc::new(ephemeral_key),
            http_client: HttpClient::new()?,
        })
    }
}
