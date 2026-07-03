use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::http::{StatusCode, header};
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

    #[error("l'acceptation des conditions générales d'utilisation est requise")]
    TermsNotAccepted,

    #[error("la version des conditions générales d'utilisation acceptée n'est pas la version courante")]
    TermsVersionMismatch,

    #[error("compte en attente de validation par un administrateur")]
    AccountPending,

    #[error("compte désactivé")]
    AccountDisabled,

    #[error("vous n'êtes pas autorisé à vous connecter avec cet appareil")]
    DeviceNotAllowed,

    #[error("trop de requêtes, réessayez plus tard")]
    TooManyRequests { retry_after_secs: u64 },
    #[error("erreur interne")]
    Internal,
}

impl From<JsonRejection> for AppError {
    fn from(rejection: JsonRejection) -> Self {
        let message = match rejection {
            JsonRejection::JsonDataError(_) => {
                "Données invalides : un ou plusieurs champs sont incorrects ou manquants."
            }
            JsonRejection::JsonSyntaxError(_) => "Le corps de la requête n'est pas un JSON valide.",
            JsonRejection::MissingJsonContentType(_) => {
                "En-tête « Content-Type: application/json » manquant."
            }
            _ => "Requête invalide.",
        };
        AppError::Validation(message.to_string())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error) = match &self {
            AppError::Validation(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            AppError::InvalidToken => (StatusCode::UNAUTHORIZED, "unauthorized"),
            AppError::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
            AppError::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
            AppError::TermsNotAccepted => (StatusCode::UNPROCESSABLE_ENTITY, "terms_not_accepted"),
            AppError::TermsVersionMismatch => {
                (StatusCode::UNPROCESSABLE_ENTITY, "terms_version_mismatch")
            }
            AppError::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
            AppError::AccountPending => (StatusCode::FORBIDDEN, "account_pending"),
            AppError::AccountDisabled => (StatusCode::FORBIDDEN, "account_disabled"),
            AppError::DeviceNotAllowed => (StatusCode::FORBIDDEN, "device_not_allowed"),
            AppError::TooManyRequests { .. } => (StatusCode::TOO_MANY_REQUESTS, "too_many_requests"),
            AppError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };
        let body = json!({ "error": error, "message": self.to_string() });
        if let AppError::TooManyRequests { retry_after_secs } = self {
            return (
                status,
                [(header::RETRY_AFTER, retry_after_secs.to_string())],
                Json(body),
            )
                .into_response();
        }
        (status, Json(body)).into_response()
    }
}
