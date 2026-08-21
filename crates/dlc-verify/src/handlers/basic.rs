use axum::response::IntoResponse;
use serde_json::json;

pub(crate) async fn health() -> impl IntoResponse {
    axum::Json(json!({"status": "healthy"}))
}
