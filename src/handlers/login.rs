use crate::domain::role::Portal;
use crate::domain::user::{AccountStatus, normalize_email};
use crate::error::AppError;
use crate::handlers::session::{Session, create_session};
use crate::services::{password, whitelist};
use crate::state::AppState;
use crate::validation;
use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::LazyLock;
use validator::Validate;

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
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    payload: Result<Json<LoginRequest>, JsonRejection>,
) -> Result<Session, AppError> {
    let Json(request) = payload?;
    validation::check(&request)?;

    let client_ip = state.trusted_proxies.resolve(peer, &headers);
    state
        .rate_limiters
        .login
        .enforce(format!("{client_ip}|{}", normalize_email(&request.email)))?;

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

    let token_ip = if user.whitelist_only {
        if !whitelist::ip_allowed(client_ip, &user.allowed_ips) {
            return Err(AppError::DeviceNotAllowed);
        }
        Some(client_ip.to_string())
    } else {
        if let Some(id) = user.id
            && !whitelist::ip_allowed(client_ip, &user.allowed_ips)
            && let Err(e) = state.users.add_allowed_ip(id, &client_ip.to_string()).await
        {
            tracing::warn!(error = %e, "Auto-ajout de l'IP à la whitelist en échec");
        }
        None
    };

    if let Some(user_id) = user.id {
        let portals: Vec<String> = user
            .roles
            .iter()
            .filter(|role| Portal::ALL.iter().any(|p| p.role_name() == role.as_str()))
            .cloned()
            .collect();
        if let Err(e) = state.login_events.record(user_id, &portals).await {
            tracing::warn!(error = %e, "Enregistrement de l'événement de connexion en échec");
        }
    }

    create_session(&state, &user, token_ip).await
}
