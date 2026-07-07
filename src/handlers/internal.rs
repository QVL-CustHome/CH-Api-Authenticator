use crate::error::AppError;
use crate::state::AppState;
use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

#[derive(Deserialize)]
pub struct ResolveRequest {
    pub ids: Vec<String>,
}

#[derive(Serialize)]
pub struct ResolvedUser {
    pub user_id: String,
    pub name: String,
    pub email: String,
}

pub async fn resolve_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ResolveRequest>,
) -> Result<Json<Vec<ResolvedUser>>, AppError> {
    let provided = headers
        .get("x-internal-secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !is_authorized(provided, &state.settings.secrets.internal_api_secret) {
        return Err(AppError::Forbidden("accès interne refusé"));
    }

    let mut out = Vec::new();
    for id in body.ids.iter().take(1000) {
        let Ok(oid) = ObjectId::parse_str(id) else {
            continue;
        };
        if let Some(user) = state
            .users
            .find_by_id(oid)
            .await
            .map_err(|_| AppError::Internal)?
        {
            out.push(ResolvedUser {
                user_id: user.id.map(|i| i.to_hex()).unwrap_or_default(),
                name: user.name,
                email: user.email,
            });
        }
    }
    Ok(Json(out))
}

fn is_authorized(provided: &str, expected: &str) -> bool {
    if provided.is_empty() {
        return false;
    }
    provided.as_bytes().ct_eq(expected.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::is_authorized;

    const EXPECTED: &str = "s3cr3t-internal-token";

    #[test]
    fn correct_secret_is_authorized() {
        assert!(is_authorized(EXPECTED, EXPECTED));
    }

    #[test]
    fn wrong_secret_same_length_is_rejected() {
        let wrong = "s3cr3t-internal-toXYZ";
        assert_eq!(wrong.len(), EXPECTED.len());
        assert!(!is_authorized(wrong, EXPECTED));
    }

    #[test]
    fn wrong_secret_different_length_is_rejected() {
        let wrong = "short";
        assert_ne!(wrong.len(), EXPECTED.len());
        assert!(!is_authorized(wrong, EXPECTED));
    }

    #[test]
    fn empty_secret_is_rejected() {
        assert!(!is_authorized("", EXPECTED));
    }
}
