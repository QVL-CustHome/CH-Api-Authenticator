//! Erreurs applicatives converties en réponses HTTP uniformes `{"error", "message"}`.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("requête invalide : {0}")]
    Validation(String),
    /// Toujours le même message, quelle que soit la cause (anti-énumération, US-03).
    #[error("identifiants invalides")]
    Unauthorized,
    /// Token absent, malformé, expiré, falsifié ou lié à une autre IP (US-05).
    #[error("token invalide ou expiré")]
    InvalidToken,
    /// Token valide mais accès refusé : aucun rôle sur le portail (US-05),
    /// ou endpoint réservé au super-admin (US-13).
    #[error("{0}")]
    Forbidden(&'static str),
    #[error("{0}")]
    Conflict(&'static str),
    /// Ressource inexistante (US-20).
    #[error("{0}")]
    NotFound(&'static str),
    /// Identifiants valides mais compte en attente de validation (US-8.1).
    #[error("compte en attente de validation par un administrateur")]
    AccountPending,
    /// Identifiants valides mais compte désactivé par un administrateur (US-8.1).
    #[error("compte désactivé")]
    AccountDisabled,
    /// Identifiants valides mais appareil (IP) non autorisé pour un compte
    /// restreint par whitelist. Renvoyé APRÈS vérification du mot de passe,
    /// donc sans fuite d'énumération.
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
