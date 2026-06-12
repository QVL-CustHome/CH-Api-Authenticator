use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("requête invalide : {0}")]
    Validation(String),

    #[error("identifiants invalides")]
    Unauthorized,

    #[error("token invalide ou expiré")]
    InvalidToken,

    #[error("{0}")]
    Forbidden(&'static str),
    #[error("{0}")]
    Conflict(&'static str),

    #[error("{0}")]
    NotFound(&'static str),

    #[error("compte en attente de validation par un administrateur")]
    AccountPending,

    #[error("compte désactivé")]
    AccountDisabled,

    #[error("vous n'êtes pas autorisé à vous connecter avec cet appareil")]
    DeviceNotAllowed,
    #[error("erreur interne")]
    Internal,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error) = match &self {
            AppError::Validation(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            AppError::InvalidToken => (StatusCode::UNAUTHORIZED, "unauthorized"),
            AppError::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
            AppError::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
            AppError::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
            AppError::AccountPending => (StatusCode::FORBIDDEN, "account_pending"),
            AppError::AccountDisabled => (StatusCode::FORBIDDEN, "account_disabled"),
            AppError::DeviceNotAllowed => (StatusCode::FORBIDDEN, "device_not_allowed"),
            AppError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };
        let body = json!({ "error": error, "message": self.to_string() });
        (status, Json(body)).into_response()
    }
}
