//! Sessions longues : émission du couple access + refresh (login US-03/US-19),
//! rotation (`POST /refresh`) et déconnexion (`POST /logout`).

use crate::domain::user::User;
use crate::error::AppError;
use crate::handlers::login::client_ip_from_headers;
use crate::repository::refresh_tokens::RotationOutcome;
use crate::services::{secure_token, whitelist};
use crate::state::AppState;
use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::{HeaderMap, header};
use axum::response::{AppendHeaders, IntoResponse};
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;

#[derive(Serialize)]
pub struct SessionBody {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    /// Refresh token opaque (US-19) — aussi posé en cookie HttpOnly.
    pub refresh_token: String,
    pub refresh_expires_in: u64,
}

/// Couple body + cookies prêt à répondre (login et refresh).
pub struct Session {
    pub body: SessionBody,
    pub cookies: [String; 2],
}

impl IntoResponse for Session {
    fn into_response(self) -> axum::response::Response {
        let [access, refresh] = self.cookies;
        (
            AppendHeaders([(header::SET_COOKIE, access), (header::SET_COOKIE, refresh)]),
            Json(self.body),
        )
            .into_response()
    }
}

/// Émet un access token JWT + un refresh token opaque (nouvelle famille).
pub async fn create_session(
    state: &AppState,
    user: &User,
    token_ip: Option<String>,
) -> Result<Session, AppError> {
    create_session_in_family(state, user, token_ip, ObjectId::new()).await
}

/// Variante rotation : le nouveau refresh token reste dans la famille du login.
pub async fn create_session_in_family(
    state: &AppState,
    user: &User,
    token_ip: Option<String>,
    family_id: ObjectId,
) -> Result<Session, AppError> {
    let access_token = state.jwt.issue(user, token_ip).map_err(|e| {
        tracing::error!(error = %e, "Émission du token en échec");
        AppError::Internal
    })?;

    let refresh_token = secure_token::generate();
    let refresh_ttl = Duration::from_secs(state.settings.config.token.refresh_ttl_days * 24 * 3600);
    state
        .refresh_tokens
        .create(
            user.id.expect("utilisateur persisté : id renseigné"),
            family_id,
            &secure_token::hash(&refresh_token),
            refresh_ttl,
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Enregistrement du refresh token en échec");
            AppError::Internal
        })?;

    let token_config = &state.settings.config.token;
    let cookies = [
        build_cookie(
            &token_config.cookie_name,
            &access_token,
            state.jwt.ttl_seconds(),
            token_config.cookie_secure,
        ),
        build_cookie(
            &token_config.refresh_cookie_name,
            &refresh_token,
            refresh_ttl.as_secs(),
            token_config.cookie_secure,
        ),
    ];

    Ok(Session {
        body: SessionBody {
            access_token,
            token_type: "Bearer",
            expires_in: state.jwt.ttl_seconds(),
            refresh_token,
            refresh_expires_in: refresh_ttl.as_secs(),
        },
        cookies,
    })
}

// Pas de derive Debug : un token ne doit jamais fuiter dans les logs.
#[derive(Deserialize, Default)]
pub struct RefreshRequest {
    #[serde(default)]
    pub refresh_token: Option<String>,
}

/// `POST /refresh` → rotation : l'ancien refresh token est révoqué, un
/// nouveau couple access + refresh est émis. La réutilisation d'un token
/// déjà tourné révoque toute la famille (vol suspecté).
pub async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<RefreshRequest>, JsonRejection>,
) -> Result<impl IntoResponse, AppError> {
    let body = match payload {
        Ok(Json(request)) => request,
        // Body absent : le cookie suffit (chemin navigateur).
        Err(_) => RefreshRequest::default(),
    };

    let token = body
        .refresh_token
        .filter(|t| !t.trim().is_empty())
        .or_else(|| cookie_value(&headers, &state.settings.config.token.refresh_cookie_name))
        .ok_or(AppError::InvalidToken)?;

    let outcome = state
        .refresh_tokens
        .consume_for_rotation(&secure_token::hash(&token))
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Rotation du refresh token en échec");
            AppError::Internal
        })?;

    let consumed = match outcome {
        RotationOutcome::Rotated(token) => token,
        RotationOutcome::ReuseDetected(token) => {
            let revoked = state
                .refresh_tokens
                .revoke_family(token.family_id)
                .await
                .unwrap_or(0);
            tracing::warn!(
                user_id = %token.user_id,
                family_id = %token.family_id,
                revoked,
                "Réutilisation d'un refresh token déjà tourné : famille révoquée (vol suspecté)"
            );
            return Err(AppError::InvalidToken);
        }
        RotationOutcome::Unknown => return Err(AppError::InvalidToken),
    };

    // Les rôles sont relus en base : un changement d'attribution (US-20)
    // est pris en compte dès la rotation suivante.
    let user = state
        .users
        .find_by_id(consumed.user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Lecture utilisateur en échec");
            AppError::Internal
        })?;
    let Some(user) = user else {
        state
            .refresh_tokens
            .revoke_family(consumed.family_id)
            .await
            .ok();
        return Err(AppError::InvalidToken);
    };

    // Comptes whitelist : mêmes exigences qu'au login (US-04). Un échec
    // consomme la rotation — il faudra se reconnecter depuis une IP valide.
    let token_ip = if user.whitelist_only {
        let Some(client_ip) = client_ip_from_headers(&headers) else {
            return Err(AppError::InvalidToken);
        };
        if !whitelist::ip_allowed(client_ip, &user.allowed_ips) {
            return Err(AppError::InvalidToken);
        }
        Some(client_ip.to_string())
    } else {
        None
    };

    create_session_in_family(&state, &user, token_ip, consumed.family_id).await
}

/// `POST /logout` → révoque la famille du refresh token présenté (cookie ou
/// body) et expire les cookies. Toujours `200`, même sans token exploitable.
pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<RefreshRequest>, JsonRejection>,
) -> impl IntoResponse {
    let body = payload.map(|Json(r)| r).unwrap_or_default();
    let token = body
        .refresh_token
        .filter(|t| !t.trim().is_empty())
        .or_else(|| cookie_value(&headers, &state.settings.config.token.refresh_cookie_name));

    if let Some(token) = token
        && let Ok(Some(found)) = state
            .refresh_tokens
            .find_by_hash(&secure_token::hash(&token))
            .await
    {
        state
            .refresh_tokens
            .revoke_family(found.family_id)
            .await
            .ok();
        tracing::info!(user_id = %found.user_id, "Déconnexion : famille de refresh tokens révoquée");
    }

    let token_config = &state.settings.config.token;
    let expired = [
        build_cookie(&token_config.cookie_name, "", 0, token_config.cookie_secure),
        build_cookie(
            &token_config.refresh_cookie_name,
            "",
            0,
            token_config.cookie_secure,
        ),
    ];
    (
        AppendHeaders([
            (header::SET_COOKIE, expired[0].clone()),
            (header::SET_COOKIE, expired[1].clone()),
        ]),
        Json(json!({ "message": "Déconnecté." })),
    )
}

/// Cookie HttpOnly (Max-Age=0 → suppression côté navigateur).
fn build_cookie(name: &str, value: &str, max_age: u64, secure: bool) -> String {
    let mut cookie = format!("{name}={value}; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age}");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// Valeur d'un cookie par nom.
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;
    cookies.split(';').find_map(|pair| {
        let (cookie_name, value) = pair.trim().split_once('=')?;
        let value = value.trim();
        (cookie_name == name && !value.is_empty()).then(|| value.to_string())
    })
}
