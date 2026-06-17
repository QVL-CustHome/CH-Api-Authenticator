use crate::domain::user::{AccountStatus, User};
use crate::error::AppError;
use crate::repository::users::RepositoryError;
use crate::services::password;
use crate::state::AppState;
use crate::validation;
use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::json;
use validator::Validate;

#[derive(Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(length(min = 1, message = "le nom est requis"))]
    pub name: String,
    #[validate(email(message = "format d'email invalide"))]
    pub email: String,
    #[validate(custom(function = "crate::validation::validate_password_strength"))]
    pub password: String,
}

pub async fn register(
    State(state): State<AppState>,
    payload: Result<Json<RegisterRequest>, JsonRejection>,
) -> Result<impl IntoResponse, AppError> {

    let Json(request) = payload?;

    let registration_enabled = state
        .settings_repo
        .registration_enabled()
        .await
        .map_err(|_| AppError::Internal)?;
    if !registration_enabled {
        return Err(AppError::Forbidden("les inscriptions sont désactivées"));
    }

    validation::check(&request)?;
    if request.name.trim().is_empty() {
        return Err(AppError::Validation("le nom est requis".to_string()));
    }

    let password_hash = password::hash(&request.password).map_err(|_| AppError::Internal)?;

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
