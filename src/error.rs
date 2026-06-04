//! Erreurs applicatives converties en réponses HTTP uniformes `{"error", "message"}`.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

// Consommé à partir de US-02 (register) ; les variantes s'étofferont avec les US.
#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("requête invalide : {0}")]
    Validation(String),
    #[error("erreur interne")]
    Internal,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error) = match &self {
            AppError::Validation(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            AppError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };
        let body = json!({ "error": error, "message": self.to_string() });
        (status, Json(body)).into_response()
    }
}
