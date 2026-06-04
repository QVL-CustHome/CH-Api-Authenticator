//! Gestion du mot de passe : changement authentifié (US-15),
//! réinitialisation par email — demande (US-17) et consommation (US-18).

use crate::error::AppError;
use crate::middleware::auth::AuthUser;
use crate::services::{password, secure_token};
use crate::state::AppState;
use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use mongodb::bson::oid::ObjectId;
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;

/// Taille minimale du mot de passe (cohérent avec /register).
const MIN_PASSWORD_CHARS: usize = 8;

#[derive(Deserialize)]
pub struct ForgotRequest {
    pub email: String,
}

// Pas de derive Debug : le mot de passe ne doit jamais fuiter dans les logs.
#[derive(Deserialize)]
pub struct ResetRequest {
    pub token: String,
    pub new_password: String,
}

// Pas de derive Debug : les mots de passe ne doivent jamais fuiter dans les logs.
#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

/// `PUT /password` (authentifié, US-15) → change le mot de passe en prouvant
/// que l'ancien est connu. `401` générique si l'ancien est faux.
pub async fn change(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    payload: Result<Json<ChangePasswordRequest>, JsonRejection>,
) -> Result<impl IntoResponse, AppError> {
    let Json(request) = payload.map_err(|e| AppError::Validation(e.body_text()))?;

    if request.new_password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(AppError::Validation(
            "mot de passe trop court (minimum 8 caractères)".to_string(),
        ));
    }

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

    // US-19 : toutes les sessions longues tombent avec l'ancien mot de passe.
    if let Err(e) = state.refresh_tokens.revoke_all_for_user(user_id).await {
        tracing::error!(error = %e, "Révocation des refresh tokens en échec");
    }

    tracing::info!(user_id = %user_id, "Mot de passe changé");
    Ok((
        StatusCode::OK,
        Json(json!({ "message": "Mot de passe changé." })),
    ))
}

/// `POST /password/forgot` → TOUJOURS `202` (anti-énumération) : la réponse
/// est identique que l'email existe ou non. Si le compte existe, un token
/// one-time est enregistré (hashé) et le lien part par email.
pub async fn forgot(
    State(state): State<AppState>,
    payload: Result<Json<ForgotRequest>, JsonRejection>,
) -> Result<impl IntoResponse, AppError> {
    let Json(request) = payload.map_err(|e| AppError::Validation(e.body_text()))?;

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

        // Envoi détaché : la latence SMTP ne doit ni retarder le 202
        // ni révéler par le timing que le compte existe.
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

/// `POST /password/reset` → consomme le token one-time et pose le nouveau
/// mot de passe. `400` strictement générique pour un token inconnu, expiré
/// ou déjà utilisé — sans distinguer la cause (US-18).
pub async fn reset(
    State(state): State<AppState>,
    payload: Result<Json<ResetRequest>, JsonRejection>,
) -> Result<impl IntoResponse, AppError> {
    let Json(request) = payload.map_err(|e| AppError::Validation(e.body_text()))?;

    // Validé AVANT de consommer : un mot de passe trop court ne doit pas
    // brûler le token (l'utilisateur peut réessayer avec le même lien).
    if request.new_password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(AppError::Validation(
            "mot de passe trop court (minimum 8 caractères)".to_string(),
        ));
    }

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
        // Compte supprimé entre-temps : même réponse générique que token invalide.
        return Err(AppError::Validation("token invalide ou expiré".to_string()));
    }

    // US-19 : toutes les sessions longues tombent avec l'ancien mot de passe.
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
