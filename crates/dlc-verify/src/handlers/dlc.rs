//! Endpoints for verifying DLC loan contracts.

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};

use crate::btc::{self, BitcoinNetwork};
use crate::decision::{self, Decision};
use crate::dlc::verify::{self, VerifyOptions};
use crate::response::AppError;
use crate::state::AppState;

/// A request to verify a contract, and optionally its collateral on chain.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VerifyRequest {
    /// Hex-encoded `DlcOffer`.
    offer_hex: String,
    /// Hex-encoded `DlcAccept`.
    accept_hex: String,
    /// Hex-encoded `DlcSign`, when the contract has reached that stage.
    #[serde(default)]
    sign_hex: Option<String>,
    /// Oracle key the contract must reference.
    #[serde(default)]
    expected_oracle_pubkey: Option<String>,
    /// Network used to render addresses. Defaults to the offer's chain hash.
    #[serde(default)]
    network: Option<String>,
    /// Chain to query for the collateral transaction.
    #[serde(default)]
    bitcoin_network: Option<BitcoinNetwork>,
    /// Collateral transaction to look for. Defaults to the contract's own fund
    /// transaction.
    #[serde(default)]
    btc_txid: Option<String>,
}

/// A signature from the enclave over the exact bytes it returned.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AppProof {
    /// Signature algorithm.
    algorithm: &'static str,
    /// The enclave's ephemeral public key, sealed to this binary at boot.
    #[serde(with = "qos_hex::serde")]
    public_key: Vec<u8>,
    /// The exact canonical JSON that was signed.
    payload: String,
    /// Signature over `payload`.
    #[serde(with = "qos_hex::serde")]
    signature: Vec<u8>,
}

/// A verification result together with the enclave's signature over it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AttestedDecision {
    /// The verdict.
    #[serde(flatten)]
    decision: Decision,
    /// Proof the verdict came from this enclave.
    proof: AppProof,
}

/// Verify a contract without consulting the chain.
///
/// Deterministic and free of I/O, so the same messages always produce the same verdict.
pub(crate) async fn verify_contract(
    State(state): State<AppState>,
    Json(request): Json<VerifyRequest>,
) -> Result<Json<AttestedDecision>, AppError> {
    let dlc = verify::verify_dlc(
        &request.offer_hex,
        &request.accept_hex,
        request.sign_hex.as_deref(),
        &VerifyOptions {
            expected_oracle_pubkey: request.expected_oracle_pubkey.clone(),
            network: request.network.clone(),
        },
    );

    attest(&state, decision::decide(dlc, None)).map(Json)
}

/// Verify a contract and confirm its collateral is locked on chain.
///
/// The chain lookup happens inside the enclave over egress, so the caller cannot
/// influence what the chain appears to say.
pub(crate) async fn verify_loan(
    State(state): State<AppState>,
    Json(request): Json<VerifyRequest>,
) -> Result<Json<AttestedDecision>, AppError> {
    let dlc = verify::verify_dlc(
        &request.offer_hex,
        &request.accept_hex,
        request.sign_hex.as_deref(),
        &VerifyOptions {
            expected_oracle_pubkey: request.expected_oracle_pubkey.clone(),
            network: request.network.clone(),
        },
    );

    // Prefer the caller's txid, but fall back to the fund transaction the contract itself
    // implies. In production the two are the same and the caller need not supply one.
    let txid = request
        .btc_txid
        .as_deref()
        .map(str::trim)
        .filter(|txid| !txid.is_empty())
        .map(ToString::to_string)
        .or_else(|| dlc.fund_txid.clone());

    let inclusion = match txid {
        Some(txid) => {
            let network = request.bitcoin_network.unwrap_or_default();
            // The funding script and value tie the transaction to this contract rather
            // than merely proving that some transaction confirmed.
            let expected_spk = dlc
                .funding_script
                .as_deref()
                .and_then(|script| qos_hex::decode(script).ok())
                .map(|script| {
                    bitcoin::ScriptBuf::from_bytes(script)
                        .to_p2wsh()
                        .to_hex_string()
                });
            Some(
                btc::check_inclusion(
                    &state.http_client,
                    network,
                    &txid,
                    expected_spk.as_deref(),
                    dlc.fund_output_value,
                )
                .await,
            )
        }
        None => None,
    };

    attest(&state, decision::decide(dlc, inclusion)).map(Json)
}

/// Sign a decision with the enclave's ephemeral key.
///
/// The signed bytes are returned verbatim as `proof.payload` so a client can verify the
/// signature without reproducing our serialization.
fn attest(state: &AppState, decision: Decision) -> Result<AttestedDecision, AppError> {
    let payload_bytes = qos_json::to_vec(&decision)
        .map_err(|e| AppError::internal(format!("failed to serialize decision: {e}")))?;
    let signature = state
        .ephemeral_key
        .sign(&payload_bytes)
        .map_err(|e| AppError::internal(format!("failed to sign decision: {e:?}")))?;
    let payload = String::from_utf8(payload_bytes)
        .map_err(|e| AppError::internal(format!("decision payload is not UTF-8: {e}")))?;

    Ok(AttestedDecision {
        decision,
        proof: AppProof {
            algorithm: "P256",
            public_key: state.ephemeral_key.public_key().to_bytes(),
            payload,
            signature,
        },
    })
}
