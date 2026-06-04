//! Connexion : vÃ©rification des identifiants et Ã©mission du JWT (US-03).

use crate::error::AppError;
use crate::services::{password, whitelist};
use crate::state::AppState;
use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::{HeaderMap, header};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::LazyLock;

/// IP client rÃ©elle, transmise par la Gateway (logique trusted_proxies, US-10 cÃ´tÃ© Gateway).
pub const CLIENT_IP_HEADER: &str = "x-client-ip";

// Pas de derive Debug : le mot de passe ne doit jamais fuiter dans les logs.
#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
}

/// Hash factice vÃ©rifiÃ© quand l'email est inconnu, pour que la durÃ©e de
/// rÃ©ponse ne rÃ©vÃ¨le pas l'existence du compte (anti-Ã©numÃ©ration par timing).
static DUMMY_HASH: LazyLock<String> =
    LazyLock::new(|| password::hash("dummy-timing-equalizer").expect("hash factice"));

/// `POST /login` â†’ `200 {access_token, token_type, expires_in}` + cookie HttpOnly.
///
/// Anti-Ã©numÃ©ration : email inconnu et mot de passe erronÃ© produisent
/// EXACTEMENT la mÃªme rÃ©ponse `401` (US-03), et la whitelist KO aussi (US-04).
pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<LoginRequest>, JsonRejection>,
) -> Result<impl IntoResponse, AppError> {
    let Json(request) = payload.map_err(|e| AppError::Validation(e.body_text()))?;

    let user = state
        .users
        .find_by_email(&request.email)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Recherche utilisateur en Ã©chec");
            AppError::Internal
        })?;

    let Some(user) = user else {
        // Ã‰galise le temps de rÃ©ponse avec le chemin Â« mot de passe vÃ©rifiÃ© Â».
        password::verify(&request.password, &DUMMY_HASH);
        return Err(AppError::Unauthorized);
    };

    if !password::verify(&request.password, &user.password_hash) {
        return Err(AppError::Unauthorized);
    }

    // US-04 : compte restreint par whitelist â€” IP requise et autorisÃ©e, sinon 401
    // gÃ©nÃ©rique (indistinguable d'un mauvais mot de passe). L'IP de login est
    // alors liÃ©e au token (claim `ip`) et revÃ©rifiÃ©e au /validate (US-05).
    let token_ip = if user.whitelist_only {
        let Some(client_ip) = client_ip(&headers) else {
            return Err(AppError::Unauthorized);
        };
        if !whitelist::ip_allowed(client_ip, &user.allowed_ips) {
            return Err(AppError::Unauthorized);
        }
        Some(client_ip.to_string())
    } else {
        None
    };

    let access_token = state.jwt.issue(&user, token_ip).map_err(|e| {
        tracing::error!(error = %e, "Ã‰mission du token en Ã©chec");
        AppError::Internal
    })?;

    let cookie = build_cookie(&state, &access_token);
    let body = LoginResponse {
        access_token,
        token_type: "Bearer",
        expires_in: state.jwt.ttl_seconds(),
    };

    Ok(([(header::SET_COOKIE, cookie)], Json(body)))
}

/// IP client depuis le header `X-Client-IP` (illisible ou absent â†’ `None`).
fn client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get(CLIENT_IP_HEADER)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Cookie HttpOnly lu par la Gateway (US-11 cÃ´tÃ© Gateway).
/// `Secure` est configurable pour permettre le dev local sans HTTPS.
fn build_cookie(state: &AppState, token: &str) -> String {
    let token_config = &state.settings.config.token;
    let mut cookie = format!(
        "{}={}; HttpOnly; SameSite=Lax; Path=/; Max-Age={}",
        token_config.cookie_name,
        token,
        state.jwt.ttl_seconds()
    );
    if token_config.cookie_secure {
        cookie.push_str("; Secure");
    }
    cookie
}
