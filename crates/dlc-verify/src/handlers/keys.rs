use crate::attestation::{self, AttestationMaterial};
use crate::response::AppError;
use crate::state::AppState;
use axum::{
    Json,
    extract::{Query, State},
};
use serde::{Deserialize, Serialize};

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

/// Optional caller-supplied nonce, so a client can prove the document is fresh.
#[derive(Debug, Deserialize)]
pub(crate) struct AttestationQuery {
    /// Hex-encoded nonce to echo into the attestation document.
    #[serde(default)]
    nonce: Option<String>,
}

/// Serve the material a client needs to check this enclave.
///
/// Deliberately returns evidence rather than a verdict: an enclave attesting to its own
/// trustworthiness proves nothing. See [`crate::attestation`] and the `attest-verify` crate.
pub(crate) async fn attestation(
    State(state): State<AppState>,
    Query(query): Query<AttestationQuery>,
) -> Result<Json<AttestationMaterial>, AppError> {
    let nonce = match query
        .nonce
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
    {
        Some(hex) => Some(
            qos_hex::decode(hex)
                .map_err(|e| AppError::bad_request(format!("nonce must be hex: {e:?}")))?,
        ),
        None => None,
    };

    // Bind the key this app signs verdicts with, so a client can connect a signed verdict
    // to the attested enclave rather than taking the link on trust.
    let public_key = state.ephemeral_key.public_key().to_bytes();
    let manifest = attestation::read_manifest();

    Ok(Json(attestation::attestation_material(
        &public_key,
        nonce.as_deref(),
        manifest.as_deref(),
    )))
}
