//! HTTP routing.

use crate::handlers::{app_key, health, verify_contract, verify_loan};
use axum::{
    Router,
    routing::{get, post},
};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::Level;

pub use crate::state::AppState;

/// Build the application router.
///
/// CORS is permissive because the demo frontend is served from GitHub Pages, a different
/// origin from the enclave. Every endpoint is a read-only verification, and the enclave
/// holds no per-user state or credentials that an origin could be trusted with.
pub fn router_with_state(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/app_key", get(app_key))
        .route("/dlc/verify", post(verify_contract))
        .route("/dlc/verify_loan", post(verify_loan))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_request(DefaultOnRequest::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(state)
}
