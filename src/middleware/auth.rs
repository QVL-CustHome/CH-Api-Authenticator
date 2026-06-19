use crate::error::AppError;
use crate::services::jwt::Claims;
use crate::state::AppState;
use axum::extract::FromRequestParts;
use axum::http::header;
use axum::http::request::Parts;

pub struct AuthUser(pub Claims);

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let cookie_name = &state.settings.config.token.cookie_name;
        let authorization = header_value(parts, header::AUTHORIZATION);
        let cookie = header_value(parts, header::COOKIE);
        let token = extract_token(authorization.as_deref(), cookie.as_deref(), cookie_name)
            .ok_or(AppError::InvalidToken)?;
        let claims = state
            .jwt
            .validate(&token)
            .map_err(|_| AppError::InvalidToken)?;
        Ok(AuthUser(claims))
    }
}

pub const ADMIN_PORTAL: &str = "portail_admin";

pub const ADMIN_ROLE: &str = "admin";

pub struct PortalAdmin(pub Claims);

impl FromRequestParts<AppState> for PortalAdmin {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let AuthUser(claims) = AuthUser::from_request_parts(parts, state).await?;
        let is_admin = claims.roles.iter().any(|r| r == ADMIN_ROLE);
        if !is_admin {
            return Err(AppError::Forbidden("accès réservé aux administrateurs"));
        }
        Ok(PortalAdmin(claims))
    }
}

fn header_value(parts: &Parts, name: header::HeaderName) -> Option<String> {
    parts
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn extract_token(
    authorization_header: Option<&str>,
    cookie_header: Option<&str>,
    cookie_name: &str,
) -> Option<String> {
    if let Some(token) = authorization_header.and_then(token_from_bearer) {
        return Some(token);
    }
    cookie_header.and_then(|cookies| token_from_cookie(cookies, cookie_name))
}

fn token_from_bearer(header_value: &str) -> Option<String> {
    let token = header_value.strip_prefix("Bearer ")?.trim();
    (!token.is_empty()).then(|| token.to_string())
}

fn token_from_cookie(cookie_header: &str, cookie_name: &str) -> Option<String> {
    cookie_header.split(';').find_map(|pair| {
        let (name, value) = pair.trim().split_once('=')?;
        let value = value.trim();
        (name == cookie_name && !value.is_empty()).then(|| value.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        Config, EmailConfig, RegistrationConfig, Secrets, ServerConfig, Settings, TokenConfig,
    };
    use crate::domain::user::User;
    use crate::services::mailer::Mailer;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use mongodb::bson::oid::ObjectId;
    use tower::ServiceExt;

    const JWT_SECRET: &str = "un-secret-de-test-suffisamment-long!!!!!";

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
                        refresh_ttl_days: 7,
                        refresh_cookie_name: "ch_refresh".to_string(),
                    },
                    registration: RegistrationConfig::default(),
                    email: EmailConfig::default(),
                    password_reset: crate::config::PasswordResetConfig::default(),
                },
                secrets: Secrets {
                    jwt_secret: JWT_SECRET.to_string(),
                    internal_api_secret: "un-secret-interne-de-test-suffisamment-long!".to_string(),
                    mongo_uri: "mongodb://localhost:27017/test".to_string(),
                    admin_email: None,
                    admin_password: None,
                    smtp_host: None,
                    smtp_port: None,
                    smtp_user: None,
                    smtp_password: None,
                },
            },
            db,
            Mailer::Dev,
        )
    }

    fn test_router(state: AppState) -> Router {
        Router::new()
            .route(
                "/protege",
                get(|AuthUser(claims): AuthUser| async move { claims.sub }),
            )
            .route(
                "/portal-admin",
                get(|PortalAdmin(claims): PortalAdmin| async move { claims.sub }),
            )
            .with_state(state)
    }

    fn token_for(state: &AppState) -> (String, String) {
        let mut user = User::new("user@test.fr", "$argon2id$hash".to_string(), Vec::new());
        user.id = Some(ObjectId::new());
        let token = state.jwt.issue(&user, None).unwrap();
        (token, user.id.unwrap().to_hex())
    }

    fn token_for_roles(state: &AppState, roles: &[&str]) -> String {
        let mut user = User::new(
            "padmin@test.fr",
            "$argon2id$hash".to_string(),
            roles.iter().map(|r| r.to_string()).collect(),
        );
        user.id = Some(ObjectId::new());
        state.jwt.issue(&user, None).unwrap()
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
        let (token, user_id) = token_for(&state);

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
        let (token, _) = token_for(&state);

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
        let (token, user_id) = token_for(&state);

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
    async fn header_non_bearer_replie_sur_le_cookie() {
        let state = test_state();
        let (token, user_id) = token_for(&state);

        let (status, body) = get_status(
            state,
            "/protege",
            &[
                ("Authorization", "Basic abc"),
                ("Cookie", &format!("ch_token={token}")),
            ],
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, user_id);
    }

    #[tokio::test]
    async fn tokens_invalides_401() {
        let state = test_state();
        let (token, _) = token_for(&state);
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
        let expired = {
            use jsonwebtoken::{Algorithm, EncodingKey, Header};
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let claims = serde_json::json!({
                "sub": "x", "roles": {},
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
    async fn garde_portal_admin_401_sans_token() {
        let state = test_state();
        let (status, _) = get_status(state, "/portal-admin", &[]).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "non authentifié : 401, pas 403"
        );
    }

    #[tokio::test]
    async fn garde_portal_admin_200_pour_role_admin_sur_portail_admin() {
        let state = test_state();
        let token = token_for_roles(&state, &["admin"]);
        let (status, _) = get_status(
            state,
            "/portal-admin",
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn garde_portal_admin_403_sans_le_bon_role() {
        let state = test_state();

        let token = token_for_roles(&state, &["editor"]);
        let (status, _) = get_status(
            state,
            "/portal-admin",
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
}
