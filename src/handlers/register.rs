//! Inscription d'un nouveau compte (US-02).

use crate::domain::user::{AccountStatus, User};
use crate::error::AppError;
use crate::repository::users::RepositoryError;
use crate::services::password;
use crate::state::AppState;
use crate::validation::{self, PASSWORD_MIN_CHARS};
use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::json;
use validator::Validate;

// Pas de derive Debug : le mot de passe ne doit jamais fuiter dans les logs.
#[derive(Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(length(min = 1, message = "le nom est requis"))]
    pub name: String,
    #[validate(email(message = "format d'email invalide"))]
    pub email: String,
    #[validate(length(
        min = "PASSWORD_MIN_CHARS",
        message = "mot de passe trop court (minimum 8 caractÃ¨res)"
    ))]
    pub password: String,
}

/// `POST /register` â†’ `201 {user_id}` | `409` email dÃ©jÃ  utilisÃ© | `400` payload invalide.
///
/// Les rÃ´les ne sont JAMAIS acceptÃ©s depuis le body : ils proviennent de
/// `registration.default_roles` (vide par dÃ©faut, attribution via super-admin au sprint 2).
pub async fn register(
    State(state): State<AppState>,
    payload: Result<Json<RegisterRequest>, JsonRejection>,
) -> Result<impl IntoResponse, AppError> {
    // JSON absent/malformÃ©/champs manquants â†’ 400 (et non 422, contrat US-02).
    let Json(request) = payload.map_err(|e| AppError::Validation(e.body_text()))?;

    validation::check(&request)?;
    if request.name.trim().is_empty() {
        return Err(AppError::Validation("le nom est requis".to_string()));
    }

    let password_hash = password::hash(&request.password).map_err(|_| AppError::Internal)?;
    // US-8.1 : tout nouveau compte est créé « en attente de validation ». Un
    // administrateur doit l'activer avant que la connexion soit possible.
    let mut user = User::new(
        &request.email,
        password_hash,
        state.settings.config.registration.default_roles.clone(),
    );
    user.name = request.name.trim().to_string();
    user.status = AccountStatus::PendingValidation;

    match state.users.insert(&user).await {
        Ok(id) => Ok((StatusCode::CREATED, Json(json!({ "user_id": id.to_hex() })))),
        Err(RepositoryError::DuplicateEmail) => Err(AppError::Conflict("email dÃ©jÃ  utilisÃ©")),
        Err(RepositoryError::Database(e)) => {
            tracing::error!(error = %e, "Insertion utilisateur en Ã©chec");
            Err(AppError::Internal)
        }
    }
}
