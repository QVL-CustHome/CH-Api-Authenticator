use crate::domain::user::AccountStatus;
use crate::error::AppError;
use crate::handlers::session::{Session, create_session};
use crate::services::{password, whitelist};
use crate::state::AppState;
use crate::validation;
use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::HeaderMap;
use serde::Deserialize;
use std::net::IpAddr;
use std::sync::LazyLock;
use validator::Validate;

pub const CLIENT_IP_HEADER: &str = "x-client-ip";

#[derive(Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email(message = "format d'email invalide"))]
    pub email: String,
    #[validate(length(min = 1, message = "mot de passe requis"))]
    pub password: String,
}

static DUMMY_HASH: LazyLock<String> =
    LazyLock::new(|| password::hash("dummy-timing-equalizer").expect("hash factice"));

pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<LoginRequest>, JsonRejection>,
) -> Result<Session, AppError> {
    let Json(request) = payload.map_err(|e| AppError::Validation(e.body_text()))?;
    validation::check(&request)?;

    let user = state
        .users
        .find_by_email(&request.email)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Recherche utilisateur en échec");
            AppError::Internal
        })?;

    let Some(user) = user else {

        password::verify(&request.password, &DUMMY_HASH);
        return Err(AppError::Unauthorized);
    };

    if !password::verify(&request.password, &user.password_hash) {
        return Err(AppError::Unauthorized);
    }

    match user.status {
        AccountStatus::Active => {}
        AccountStatus::PendingValidation => return Err(AppError::AccountPending),
        AccountStatus::Disabled => return Err(AppError::AccountDisabled),
    }

    let client_ip = client_ip_from_headers(&headers);
    let token_ip = if user.whitelist_only {

        let Some(client_ip) = client_ip else {
            return Err(AppError::DeviceNotAllowed);
        };
        if !whitelist::ip_allowed(client_ip, &user.allowed_ips) {
            return Err(AppError::DeviceNotAllowed);
        }
        Some(client_ip.to_string())
    } else {

        if let (Some(client_ip), Some(id)) = (client_ip, user.id) {
            if !whitelist::ip_allowed(client_ip, &user.allowed_ips) {
                if let Err(e) = state.users.add_allowed_ip(id, &client_ip.to_string()).await {
                    tracing::warn!(error = %e, "Auto-ajout de l'IP à la whitelist en échec");
                }
            }
        }
        None
    };

    create_session(&state, &user, token_ip).await
}

pub fn client_ip_from_headers(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get(CLIENT_IP_HEADER)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}
