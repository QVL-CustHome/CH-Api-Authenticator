//! Réinitialisation de mot de passe par email — demande (US-17).

use crate::error::AppError;
use crate::services::reset_token;
use crate::state::AppState;
use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;

#[derive(Deserialize)]
pub struct ForgotRequest {
    pub email: String,
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
        let token = reset_token::generate();
        let ttl = Duration::from_secs(state.settings.config.password_reset.ttl_minutes * 60);

        state
            .reset_tokens
            .replace_for_user(user_id, &reset_token::hash(&token), ttl)
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
