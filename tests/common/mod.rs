//! Helpers partagés par la suite d'intégration `tests/api_*.rs`.
//!
//! Chaque test travaille dans une base MongoDB jetable (instance locale),
//! supprimée en fin de test via `Database::drop`.

// Chaque binaire de test ne consomme qu'une partie des helpers.
#![allow(dead_code)]

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use ch_api_authenticator::config::{
    Config, RegistrationConfig, Secrets, ServerConfig, Settings, TokenConfig,
};
use ch_api_authenticator::domain::user::User;
use ch_api_authenticator::routes::router;
use ch_api_authenticator::services::password;
use ch_api_authenticator::state::AppState;
use http_body_util::BodyExt;
use mongodb::Database;
use mongodb::bson::oid::ObjectId;
use std::collections::HashMap;
use tower::ServiceExt;

pub const JWT_SECRET: &str = "un-secret-de-test-suffisamment-long!!!!!";
pub const PASSWORD: &str = "bon-mot-de-passe";

/// Base jetable sur la MongoDB locale (service Windows — pas de Docker).
pub async fn test_db() -> Database {
    let client = mongodb::Client::with_uri_str("mongodb://localhost:27017")
        .await
        .expect("MongoDB locale requise pour les tests d'intégration");
    client.database(&format!("ch_auth_test_{}", ObjectId::new()))
}

pub async fn test_state(db: &Database) -> AppState {
    test_state_with(db, false, HashMap::new()).await
}

pub async fn test_state_with(
    db: &Database,
    cookie_secure: bool,
    default_roles: HashMap<String, String>,
) -> AppState {
    let state = state_for_db(db, cookie_secure, default_roles);
    state.users.ensure_indexes().await.unwrap();
    state
}

/// État sans création d'index — utilisable avec une base injoignable (US-07).
pub fn state_for_db(
    db: &Database,
    cookie_secure: bool,
    default_roles: HashMap<String, String>,
) -> AppState {
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
                    cookie_secure,
                },
                registration: RegistrationConfig { default_roles },
            },
            secrets: Secrets {
                jwt_secret: JWT_SECRET.to_string(),
                mongo_uri: "mongodb://localhost:27017/test".to_string(),
                admin_email: None,
                admin_password: None,
            },
        },
        db.clone(),
    )
}

/// Base volontairement injoignable (port fermé, timeout court) pour
/// éprouver le mode dégradé (US-07).
pub fn broken_db() -> Database {
    let options = mongodb::options::ClientOptions::builder()
        .hosts(vec![mongodb::options::ServerAddress::Tcp {
            host: "localhost".to_string(),
            port: Some(1),
        }])
        .server_selection_timeout(std::time::Duration::from_millis(200))
        .build();
    mongodb::Client::with_options(options)
        .unwrap()
        .database("down")
}

/// Insère un utilisateur avec le mot de passe [`PASSWORD`] et rend l'utilisateur persisté.
pub async fn seed_user(state: &AppState, email: &str, roles: HashMap<String, String>) -> User {
    let mut user = User::new(email, password::hash(PASSWORD).unwrap(), roles);
    let id = state.users.insert(&user).await.unwrap();
    user.id = Some(id);
    user
}

pub async fn seed_whitelist_user(state: &AppState, email: &str, allowed_ips: &[&str]) -> User {
    let mut user = User::new(email, password::hash(PASSWORD).unwrap(), HashMap::new());
    user.whitelist_only = true;
    user.allowed_ips = allowed_ips.iter().map(|s| s.to_string()).collect();
    let id = state.users.insert(&user).await.unwrap();
    user.id = Some(id);
    user
}

pub async fn seed_super_admin(state: &AppState, email: &str) -> User {
    let mut user = User::new_super_admin(email, password::hash(PASSWORD).unwrap());
    let id = state.users.insert(&user).await.unwrap();
    user.id = Some(id);
    user
}

pub fn roles(entries: &[(&str, &str)]) -> HashMap<String, String> {
    entries
        .iter()
        .map(|(portal, role)| (portal.to_string(), role.to_string()))
        .collect()
}

/// Réponse HTTP dépouillée pour les assertions.
pub struct TestResponse {
    pub status: StatusCode,
    pub set_cookie: Option<String>,
    pub correlation_id: Option<String>,
    pub body: serde_json::Value,
}

/// POST JSON avec headers optionnels.
pub async fn post_json(
    app: Router,
    path: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> TestResponse {
    let mut request = Request::post(path).header(header::CONTENT_TYPE, "application/json");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    send(app, request.body(Body::from(body.to_string())).unwrap()).await
}

/// GET avec headers optionnels.
pub async fn get(app: Router, path: &str, headers: &[(&str, &str)]) -> TestResponse {
    let mut request = Request::get(path);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    send(app, request.body(Body::empty()).unwrap()).await
}

async fn send(app: Router, request: Request<Body>) -> TestResponse {
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .map(|v| v.to_str().unwrap().to_string());
    let correlation_id = response
        .headers()
        .get(ch_api_authenticator::middleware::tracing::CORRELATION_HEADER)
        .map(|v| v.to_str().unwrap().to_string());
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    TestResponse {
        status,
        set_cookie,
        correlation_id,
        body,
    }
}

/// Login via l'API et rend l'access token (chemin nominal).
pub async fn login_token(state: &AppState, email: &str) -> String {
    login_token_with(state, email, PASSWORD).await
}

pub async fn login_token_with(state: &AppState, email: &str, password: &str) -> String {
    let response = post_json(
        router(state.clone()),
        "/login",
        &format!(r#"{{"email": "{email}", "password": "{password}"}}"#),
        &[],
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "login de préparation");
    response.body["access_token"].as_str().unwrap().to_string()
}
