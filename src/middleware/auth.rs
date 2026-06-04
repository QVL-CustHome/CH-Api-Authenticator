//! Authentification interne des endpoints de l'API (US-13).
//!
//! Les routes `/api/auth/*` sont publiques côté Gateway : c'est l'Authenticator
//! qui protège lui-même ses endpoints sensibles (profil, mot de passe, admin)
//! via ces extracteurs Axum. Validation purement cryptographique — aucune I/O.
//!
//! Politique d'extraction identique à la Gateway (US-11) : le header
//! `Authorization` prime ; le cookie n'est lu que si le header est absent ;
//! un header présent mais malformé est rejeté sans repli sur le cookie.

use crate::error::AppError;
use crate::services::jwt::Claims;
use crate::state::AppState;
use axum::extract::FromRequestParts;
use axum::http::header;
use axum::http::request::Parts;

/// Utilisateur authentifié : claims du JWT validé.
pub struct AuthUser(pub Claims);

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let cookie_name = &state.settings.config.token.cookie_name;
        let token = extract_token(parts, cookie_name).ok_or(AppError::InvalidToken)?;
        let claims = state
            .jwt
            .validate(&token)
            .map_err(|_| AppError::InvalidToken)?;
        Ok(AuthUser(claims))
    }
}

/// Utilisateur authentifié ET super-admin global — garde des endpoints
/// d'administration (US-20). `403` pour tout autre compte.
pub struct SuperAdmin(pub Claims);

impl FromRequestParts<AppState> for SuperAdmin {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let AuthUser(claims) = AuthUser::from_request_parts(parts, state).await?;
        if !claims.super_admin {
            return Err(AppError::Forbidden("accès réservé au super-admin"));
        }
        Ok(SuperAdmin(claims))
    }
}

/// Header `Authorization: Bearer` prioritaire, cookie en fallback.
/// Un header présent mais malformé → `None` (pas de repli silencieux).
fn extract_token(parts: &Parts, cookie_name: &str) -> Option<String> {
    if let Some(value) = parts.headers.get(header::AUTHORIZATION) {
        let token = value.to_str().ok()?.strip_prefix("Bearer ")?.trim();
        return (!token.is_empty()).then(|| token.to_string());
    }

    let cookies = parts.headers.get(header::COOKIE)?.to_str().ok()?;
    cookies.split(';').find_map(|pair| {
        let (name, value) = pair.trim().split_once('=')?;
        let value = value.trim();
        (name == cookie_name && !value.is_empty()).then(|| value.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, RegistrationConfig, Secrets, ServerConfig, Settings, TokenConfig};
    use crate::domain::user::User;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use mongodb::bson::oid::ObjectId;
    use std::collections::HashMap;
    use tower::ServiceExt;

    const JWT_SECRET: &str = "un-secret-de-test-suffisamment-long!!!!!";

    /// État sans connexion MongoDB (client lazy) : ces extracteurs n'ont pas d'I/O.
    fn test_state() -> AppState {
        let options = mongodb::options::ClientOptions::builder()
            .hosts(vec![mongodb::options::ServerAddress::Tcp {
                host: "localhost".to_string(),
                port: Some(27017),
            }])
            .build();
        let db = mongodb::Client::with_options(options)
            .unwrap()
            .database("ch_auth_test_extractors");
        AppState::new(
            Settings {
                config: Config {
                    server: ServerConfig {
                        port: 0,
                        log_level: "INFO".to_string(),
                    },
                    token: TokenConfig {
                        ttl_minutes: 15,
                        cookie_name: "ch_token".to_string(),
                        cookie_secure: false,
                    },
                    registration: RegistrationConfig::default(),
                },
                secrets: Secrets {
                    jwt_secret: JWT_SECRET.to_string(),
                    mongo_uri: "mongodb://localhost:27017/test".to_string(),
                    admin_email: None,
                    admin_password: None,
                },
            },
            db,
        )
    }

    /// Routeur de test : une route protégée AuthUser, une route garde SuperAdmin.
    fn test_router(state: AppState) -> Router {
        Router::new()
            .route(
                "/protege",
                get(|AuthUser(claims): AuthUser| async move { claims.sub }),
            )
            .route(
                "/admin",
                get(|SuperAdmin(claims): SuperAdmin| async move { claims.sub }),
            )
            .with_state(state)
    }

    fn token_for(state: &AppState, super_admin: bool) -> (String, String) {
        let mut user = if super_admin {
            User::new_super_admin("admin@test.fr", "$argon2id$hash".to_string())
        } else {
            User::new("user@test.fr", "$argon2id$hash".to_string(), HashMap::new())
        };
        user.id = Some(ObjectId::new());
        let token = state.jwt.issue(&user, None).unwrap();
        (token, user.id.unwrap().to_hex())
    }

    async fn get_status(
        state: AppState,
        path: &str,
        headers: &[(&str, &str)],
    ) -> (StatusCode, String) {
        let mut request = Request::get(path);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = test_router(state)
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        (status, String::from_utf8_lossy(&body).to_string())
    }

    #[tokio::test]
    async fn token_valide_en_header_200_avec_claims() {
        let state = test_state();
        let (token, user_id) = token_for(&state, false);

        let (status, body) = get_status(
            state,
            "/protege",
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, user_id, "les claims sont exposés au handler");
    }

    #[tokio::test]
    async fn token_valide_en_cookie_200() {
        let state = test_state();
        let (token, _) = token_for(&state, false);

        let (status, _) = get_status(
            state,
            "/protege",
            &[("Cookie", &format!("autre=x; ch_token={token}"))],
        )
        .await;

        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn header_prime_sur_le_cookie() {
        let state = test_state();
        let (token, user_id) = token_for(&state, false);

        // Cookie pourri + header valide → le header gagne.
        let (status, body) = get_status(
            state,
            "/protege",
            &[
                ("Authorization", &format!("Bearer {token}")),
                ("Cookie", "ch_token=token-perime"),
            ],
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, user_id);
    }

    #[tokio::test]
    async fn header_malforme_401_sans_repli_cookie() {
        let state = test_state();
        let (token, _) = token_for(&state, false);

        // Header présent mais pas un Bearer : pas de repli sur le cookie valide.
        let (status, _) = get_status(
            state,
            "/protege",
            &[
                ("Authorization", "Basic abc"),
                ("Cookie", &format!("ch_token={token}")),
            ],
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn tokens_invalides_401() {
        let state = test_state();
        let (token, _) = token_for(&state, false);
        let falsifie = format!("{}AAAA", &token[..token.len() - 4]);

        for (label, headers) in [
            ("aucun token", vec![]),
            (
                "token falsifié",
                vec![("Authorization".to_string(), format!("Bearer {falsifie}"))],
            ),
            (
                "pas un JWT",
                vec![(
                    "Authorization".to_string(),
                    "Bearer nimporte.quoi".to_string(),
                )],
            ),
            (
                "cookie vide",
                vec![("Cookie".to_string(), "ch_token=".to_string())],
            ),
            (
                "autre cookie",
                vec![("Cookie".to_string(), format!("session={token}"))],
            ),
        ] {
            let header_refs: Vec<(&str, &str)> = headers
                .iter()
                .map(|(n, v)| (n.as_str(), v.as_str()))
                .collect();
            let (status, _) = get_status(state.clone(), "/protege", &header_refs).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "cas : {label}");
        }
    }

    #[tokio::test]
    async fn token_expire_401() {
        let state = test_state();
        // Token forgé avec le bon secret mais expiré.
        let expired = {
            use jsonwebtoken::{Algorithm, EncodingKey, Header};
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let claims = serde_json::json!({
                "sub": "x", "roles": {}, "super_admin": false,
                "iat": now - 3600, "exp": now - 600,
            });
            jsonwebtoken::encode(
                &Header::new(Algorithm::HS256),
                &claims,
                &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
            )
            .unwrap()
        };

        let (status, _) = get_status(
            state,
            "/protege",
            &[("Authorization", &format!("Bearer {expired}"))],
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn garde_super_admin_403_pour_un_utilisateur_normal() {
        let state = test_state();
        let (token, _) = token_for(&state, false);

        let (status, _) = get_status(
            state,
            "/admin",
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn garde_super_admin_200_pour_un_super_admin() {
        let state = test_state();
        let (token, user_id) = token_for(&state, true);

        let (status, body) = get_status(
            state,
            "/admin",
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, user_id);
    }

    #[tokio::test]
    async fn garde_super_admin_401_sans_token() {
        let state = test_state();
        let (status, _) = get_status(state, "/admin", &[]).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "non authentifié : 401, pas 403"
        );
    }
}
