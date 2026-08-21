use crate::state::AppState;
use axum::{Json, extract::State};
use serde::Serialize;

/// The enclave's public key, so clients can verify proofs without making a request that
/// produces one.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AppKeyResponse {
    algorithm: &'static str,
    #[serde(with = "qos_hex::serde")]
    public_key: Vec<u8>,
}

pub(crate) async fn app_key(State(state): State<AppState>) -> Json<AppKeyResponse> {
    Json(AppKeyResponse {
        algorithm: "P256",
        public_key: state.ephemeral_key.public_key().to_bytes(),
    })
}
