//! Profil de l'utilisateur connecté (US-14).

use crate::domain::user::User;
use crate::error::AppError;
use crate::middleware::auth::AuthUser;
use crate::repository::users::RepositoryError;
use crate::state::AppState;
use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use validator::Validate;

/// Profil exposé — jamais le `password_hash`.
#[derive(Serialize)]
pub struct MeResponse {
    pub user_id: String,
    pub email: String,
    pub roles: HashMap<String, String>,
    pub is_super_admin: bool,
    pub whitelist_only: bool,
    pub created_at: String,
}

#[derive(Deserialize, Validate)]
pub struct UpdateMeRequest {
    #[validate(email(message = "format d'email invalide"))]
    pub email: String,
}

/// `GET /me` → `200` profil de l'utilisateur du token.
pub async fn get_me(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
) -> Result<Json<MeResponse>, AppError> {
    let user = load_user(&state, &claims.sub).await?;
    Ok(Json(profile(user)))
}

/// `PUT /me` → changement d'email (seul champ modifiable ce sprint).
/// `409` si l'email est déjà utilisé, `400` si invalide.
pub async fn update_me(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    payload: Result<Json<UpdateMeRequest>, JsonRejection>,
) -> Result<Json<MeResponse>, AppError> {
    let Json(request) = payload.map_err(|e| AppError::Validation(e.body_text()))?;
    request
        .validate()
        .map_err(|_| AppError::Validation("format d'email invalide".to_string()))?;

    let id = parse_user_id(&claims.sub)?;
    let email = request.email.trim().to_lowercase();

    match state.users.update_email(id, &email).await {
        Ok(true) => {}
        // Token valide mais compte disparu : la session n'est plus exploitable.
        Ok(false) => return Err(AppError::InvalidToken),
        Err(RepositoryError::DuplicateEmail) => {
            return Err(AppError::Conflict("email déjà utilisé"));
        }
        Err(RepositoryError::Database(e)) => {
            tracing::error!(error = %e, "Mise à jour de l'email en échec");
            return Err(AppError::Internal);
        }
    }

    let user = load_user(&state, &claims.sub).await?;
    Ok(Json(profile(user)))
}

async fn load_user(state: &AppState, sub: &str) -> Result<User, AppError> {
    let id = parse_user_id(sub)?;
    state
        .users
        .find_by_id(id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Lecture du profil en échec");
            AppError::Internal
        })?
        .ok_or(AppError::InvalidToken)
}

fn parse_user_id(sub: &str) -> Result<ObjectId, AppError> {
    ObjectId::parse_str(sub).map_err(|_| AppError::InvalidToken)
}

/// Réutilisé par les endpoints admin (US-20) — jamais de `password_hash`.
pub fn profile(user: User) -> MeResponse {
    MeResponse {
        user_id: user.id.map(|id| id.to_hex()).unwrap_or_default(),
        email: user.email,
        roles: user.roles,
        is_super_admin: user.is_super_admin,
        whitelist_only: user.whitelist_only,
        created_at: user.created_at.try_to_rfc3339_string().unwrap_or_default(),
    }
}
