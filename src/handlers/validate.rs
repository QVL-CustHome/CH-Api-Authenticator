//! Validation du token pour la Gateway (US-05).
//!
//! Chemin chaud appelé à CHAQUE requête protégée : la Gateway impose un
//! timeout de 100 ms, donc AUCUNE I/O ici — validation cryptographique
//! et résolution du rôle uniquement à partir des claims du token.

use crate::error::AppError;
use crate::handlers::login::CLIENT_IP_HEADER;
use crate::state::AppState;
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, header};
use serde::Serialize;

/// Portail visé par la requête, transmis par la Gateway (US-09 côté Gateway).
pub const PORTAL_HEADER: &str = "x-portal";

/// Contrat consommé par le middleware Go de la Gateway (`auth.go`).
#[derive(Serialize)]
pub struct ValidateResponse {
    pub user_id: String,
    pub role: String,
}

/// `GET /validate` → `200 {user_id, role}` | `401` token invalide | `403` aucun rôle.
pub async fn validate(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ValidateResponse>, AppError> {
    let token = bearer_token(&headers).ok_or(AppError::InvalidToken)?;
    let claims = state
        .jwt
        .validate(token)
        .map_err(|_| AppError::InvalidToken)?;

    // US-04 : compte whitelist — le token est lié à l'IP de login,
    // l'IP courante transmise par la Gateway doit correspondre.
    if let Some(token_ip) = &claims.ip {
        let client_ip = headers
            .get(CLIENT_IP_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(str::trim);
        if client_ip != Some(token_ip.as_str()) {
            return Err(AppError::InvalidToken);
        }
    }

    // Le header X-Portal reste exigé (contrat Gateway) même si les rôles sont
    // désormais globaux : sa présence valide le contrat, sa valeur n'est pas
    // utilisée pour résoudre le rôle.
    let _portal = headers
        .get(PORTAL_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .ok_or_else(|| AppError::Validation("header X-Portal manquant".to_string()))?;

    // Rôles globaux (US-8.x) : 403 si l'utilisateur n'a aucun rôle ; sinon ils
    // sont renvoyés joints par ',' à la Gateway (X-User-Role).
    if claims.roles.is_empty() {
        return Err(AppError::Forbidden("aucun rôle attribué"));
    }
    let role = claims.roles.join(",");

    Ok(Json(ValidateResponse {
        user_id: claims.sub,
        role,
    }))
}

/// Extrait le token du header `Authorization: Bearer <token>`.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?.trim();
    (!token.is_empty()).then_some(token)
}
