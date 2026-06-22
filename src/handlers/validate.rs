use crate::domain::role::Portal;
use crate::error::AppError;
use crate::services::client_ip::CLIENT_IP_HEADER;
use crate::state::AppState;
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, header};
use serde::Serialize;

pub const PORTAL_HEADER: &str = "x-portal";

#[derive(Serialize)]
pub struct ValidateResponse {
    pub user_id: String,
    pub role: String,
}

pub async fn validate(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ValidateResponse>, AppError> {
    let token = bearer_token(&headers).ok_or(AppError::InvalidToken)?;
    let claims = state
        .jwt
        .validate(token)
        .map_err(|_| AppError::InvalidToken)?;

    if let Some(token_ip) = &claims.ip {
        let client_ip = headers
            .get(CLIENT_IP_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(str::trim);
        if client_ip != Some(token_ip.as_str()) {
            return Err(AppError::InvalidToken);
        }
    }

    let portal = headers
        .get(PORTAL_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .ok_or_else(|| AppError::Validation("header X-Portal manquant".to_string()))?;

    if claims.roles.is_empty() {
        return Err(AppError::Forbidden("aucun rôle attribué"));
    }

    if let Some(required) = Portal::from_portal_header(portal) {
        if !claims.roles.iter().any(|r| r == required.role_name()) {
            return Err(AppError::Forbidden("accès non autorisé pour ce portail"));
        }
    }

    let role = claims.roles.join(",");

    Ok(Json(ValidateResponse {
        user_id: claims.sub,
        role,
    }))
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?.trim();
    (!token.is_empty()).then_some(token)
}
