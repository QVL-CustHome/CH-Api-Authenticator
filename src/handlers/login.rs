//! Connexion : vérification des identifiants et émission de la session
//! (access token JWT + refresh token, US-03/US-19).

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

/// IP client réelle, transmise par la Gateway (logique trusted_proxies, US-10 côté Gateway).
pub const CLIENT_IP_HEADER: &str = "x-client-ip";

// Pas de derive Debug : le mot de passe ne doit jamais fuiter dans les logs.
#[derive(Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email(message = "format d'email invalide"))]
    pub email: String,
    #[validate(length(min = 1, message = "mot de passe requis"))]
    pub password: String,
}

/// Hash factice vérifié quand l'email est inconnu, pour que la durée de
/// réponse ne révèle pas l'existence du compte (anti-énumération par timing).
static DUMMY_HASH: LazyLock<String> =
    LazyLock::new(|| password::hash("dummy-timing-equalizer").expect("hash factice"));

/// `POST /login` → `200 {access_token, …, refresh_token, …}` + cookies HttpOnly.
///
/// Anti-énumération : email inconnu et mot de passe erroné produisent
/// EXACTEMENT la même réponse `401` (US-03), et la whitelist KO aussi (US-04).
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
        // Égalise le temps de réponse avec le chemin « mot de passe vérifié ».
        password::verify(&request.password, &DUMMY_HASH);
        return Err(AppError::Unauthorized);
    };

    if !password::verify(&request.password, &user.password_hash) {
        return Err(AppError::Unauthorized);
    }

    // US-04 : compte restreint par whitelist — IP requise et autorisée, sinon 401
    // générique (indistinguable d'un mauvais mot de passe). L'IP de login est
    // alors liée au token (claim `ip`) et revérifiée au /validate (US-05).
    let token_ip = if user.whitelist_only {
        let Some(client_ip) = client_ip_from_headers(&headers) else {
            return Err(AppError::Unauthorized);
        };
        if !whitelist::ip_allowed(client_ip, &user.allowed_ips) {
            return Err(AppError::Unauthorized);
        }
        Some(client_ip.to_string())
    } else {
        None
    };

    // US-19 : la session porte un access token court + un refresh token
    // opaque (nouvelle famille), tous deux posés en cookies HttpOnly.
    create_session(&state, &user, token_ip).await
}

/// IP client depuis le header `X-Client-IP` (illisible ou absent → `None`).
pub fn client_ip_from_headers(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get(CLIENT_IP_HEADER)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}
