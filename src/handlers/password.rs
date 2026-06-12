use crate::error::AppError;
use crate::middleware::auth::AuthUser;
use crate::services::{password, secure_token};
use crate::state::AppState;
use crate::validation::{self, PASSWORD_MIN_CHARS};
use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use mongodb::bson::oid::ObjectId;
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;
use validator::Validate;

#[derive(Deserialize, Validate)]
pub struct ForgotRequest {
    #[validate(email(message = "format d'email invalide"))]
    pub email: String,
}

#[derive(Deserialize, Validate)]
pub struct ResetRequest {
    #[validate(length(min = 1, message = "token requis"))]
    pub token: String,
    #[validate(length(
        min = "PASSWORD_MIN_CHARS",
        message = "mot de passe trop court (minimum 8 caractères)"
    ))]
    pub new_password: String,
}

#[derive(Deserialize, Validate)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    #[validate(length(
        min = "PASSWORD_MIN_CHARS",
        message = "mot de passe trop court (minimum 8 caractères)"
    ))]
    pub new_password: String,
}

pub async fn change(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    payload: Result<Json<ChangePasswordRequest>, JsonRejection>,
) -> Result<impl IntoResponse, AppError> {
    let Json(request) = payload.map_err(|e| AppError::Validation(e.body_text()))?;
    validation::check(&request)?;

    let user_id = ObjectId::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;
    let user = state
        .users
        .find_by_id(user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Lecture utilisateur en échec");
            AppError::Internal
        })?
        .ok_or(AppError::InvalidToken)?;

    if !password::verify(&request.current_password, &user.password_hash) {
        return Err(AppError::Unauthorized);
    }

    let password_hash = password::hash(&request.new_password).map_err(|_| AppError::Internal)?;
    if !state
        .users
        .update_password(user_id, &password_hash)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Mise à jour du mot de passe en échec");
            AppError::Internal
        })?
    {
        return Err(AppError::InvalidToken);
    }

    if let Err(e) = state.refresh_tokens.revoke_all_for_user(user_id).await {
        tracing::error!(error = %e, "Révocation des refresh tokens en échec");
    }

    tracing::info!(user_id = %user_id, "Mot de passe changé");
    Ok((
        StatusCode::OK,
        Json(json!({ "message": "Mot de passe changé." })),
    ))
}

pub async fn forgot(
    State(state): State<AppState>,
    payload: Result<Json<ForgotRequest>, JsonRejection>,
) -> Result<impl IntoResponse, AppError> {
    let Json(request) = payload.map_err(|e| AppError::Validation(e.body_text()))?;
    validation::check(&request)?;

    if let Some(user) = state
        .users
        .find_by_email(&request.email)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Recherche utilisateur en échec");
            AppError::Internal
        })?
    {
        let user_id = user.id.expect("utilisateur persisté : id renseigné");
        let token = secure_token::generate();
        let ttl = Duration::from_secs(state.settings.config.password_reset.ttl_minutes * 60);

        state
            .reset_tokens
            .replace_for_user(user_id, &secure_token::hash(&token), ttl)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Enregistrement du token de reset en échec");
                AppError::Internal
            })?;

        let link = format!("{}?token={token}", state.settings.config.password_reset.url);
        let mailer = state.mailer.clone();
        let to = user.email.clone();
        let ttl_minutes = state.settings.config.password_reset.ttl_minutes;
        tokio::spawn(async move {
            mailer
                .send(
                    &to,
                    "Réinitialisation de votre mot de passe CustHome",
                    &format!(
                        "Bonjour,\n\nPour définir un nouveau mot de passe, ouvrez ce lien \
                         (valable {ttl_minutes} minutes) :\n{link}\n\n\
                         Si vous n'êtes pas à l'origine de cette demande, ignorez cet email."
                    ),
                )
                .await;
        });
    }

    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "message": "Si un compte existe pour cet email, un lien de réinitialisation a été envoyé."
        })),
    ))
}

pub async fn reset(
    State(state): State<AppState>,
    payload: Result<Json<ResetRequest>, JsonRejection>,
) -> Result<impl IntoResponse, AppError> {
    let Json(request) = payload.map_err(|e| AppError::Validation(e.body_text()))?;

    validation::check(&request)?;

    let consumed = state
        .reset_tokens
        .consume(&secure_token::hash(&request.token))
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Consommation du token de reset en échec");
            AppError::Internal
        })?
        .ok_or_else(|| AppError::Validation("token invalide ou expiré".to_string()))?;

    let password_hash = password::hash(&request.new_password).map_err(|_| AppError::Internal)?;
    let updated = state
        .users
        .update_password(consumed.user_id, &password_hash)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Mise à jour du mot de passe en échec");
            AppError::Internal
        })?;

    if !updated {

        return Err(AppError::Validation("token invalide ou expiré".to_string()));
    }

    if let Err(e) = state
        .refresh_tokens
        .revoke_all_for_user(consumed.user_id)
        .await
    {
        tracing::error!(error = %e, "Révocation des refresh tokens en échec");
    }

    tracing::info!(user_id = %consumed.user_id, "Mot de passe réinitialisé");
    Ok((
        StatusCode::OK,
        Json(json!({ "message": "Mot de passe réinitialisé." })),
    ))
}
