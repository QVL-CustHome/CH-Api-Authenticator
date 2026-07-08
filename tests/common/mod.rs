#![allow(dead_code)]

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use ch_api_authenticator::config::{
    Config, EmailConfig, Environment, PasswordResetConfig, RegistrationConfig, Secrets,
    ServerConfig, Settings, TokenConfig,
};
use ch_api_authenticator::domain::user::User;
use ch_api_authenticator::routes::router;
use ch_api_authenticator::services::mailer::{Mailer, SentEmail};
use ch_api_authenticator::services::password;
use ch_api_authenticator::state::AppState;
use http_body_util::BodyExt;
use mongodb::Database;
use mongodb::bson::doc;
use mongodb::bson::oid::ObjectId;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

pub const JWT_SECRET: &str = "un-secret-de-test-suffisamment-long!!!!!";
pub const PASSWORD: &str = "Bon-Mot-De-Passe1";

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
    default_roles: HashMap<String, Vec<String>>,
) -> AppState {
    let state = state_for_db(db, cookie_secure, default_roles);
    state.users.ensure_indexes().await.unwrap();
    state.roles.ensure_indexes().await.unwrap();
    state.reset_tokens.ensure_indexes().await.unwrap();
    state
}

pub fn state_for_db(
    db: &Database,
    cookie_secure: bool,
    default_roles: HashMap<String, Vec<String>>,
) -> AppState {
    state_with_mailer(db, cookie_secure, default_roles, Mailer::Dev)
}

pub async fn test_state_with_outbox(db: &Database) -> (AppState, Arc<Mutex<Vec<SentEmail>>>) {
    let (mailer, outbox) = Mailer::memory();
    let state = state_with_mailer(db, false, HashMap::new(), mailer);
    state.users.ensure_indexes().await.unwrap();
    state.roles.ensure_indexes().await.unwrap();
    state.reset_tokens.ensure_indexes().await.unwrap();
    (state, outbox)
}

pub fn state_with_mailer(
    db: &Database,
    cookie_secure: bool,
    default_roles: HashMap<String, Vec<String>>,
    mailer: Mailer,
) -> AppState {
    AppState::new(
        Settings {
            config: Config {
                environment: Environment::Dev,
                server: ServerConfig {
                    port: 0,
                    log_level: "INFO".to_string(),
                },
                token: TokenConfig {
                    cookie_domain: None,
                    ttl_minutes: 15,
                    cookie_name: "ch_token".to_string(),
                    cookie_secure,
                    refresh_ttl_days: 7,
                    refresh_cookie_name: "ch_refresh".to_string(),
                    issuer: "ch-api-authenticator".to_string(),
                    audience_drive: "ch-api-drive".to_string(),
                    audience_budgy: "ch-api-budgy".to_string(),
                },
                registration: RegistrationConfig {
                    default_roles: default_roles.into_values().flatten().collect(),
                },
                email: EmailConfig::default(),
                password_reset: PasswordResetConfig::default(),
                relay: ch_api_authenticator::config::RelayConfig::default(),
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
                relay_jwt_private_key: None,
            },
            rate_limit: ch_api_authenticator::services::rate_limit::RateLimitConfig {
                login: ch_api_authenticator::services::rate_limit::RateLimitRule {
                    max: 5,
                    window: std::time::Duration::from_secs(300),
                },
                forgot: ch_api_authenticator::services::rate_limit::RateLimitRule {
                    max: 3,
                    window: std::time::Duration::from_secs(900),
                },
                refresh: ch_api_authenticator::services::rate_limit::RateLimitRule {
                    max: 30,
                    window: std::time::Duration::from_secs(60),
                },
            },
        },
        db.clone(),
        mailer,
        ch_api_authenticator::services::relay::RelayPublisher::Disabled,
    )
}

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

pub async fn seed_user(state: &AppState, email: &str, roles: HashMap<String, Vec<String>>) -> User {
    let flat: Vec<String> = roles.into_values().flatten().collect();
    let mut user = User::new(email, password::hash(PASSWORD).unwrap(), flat);
    let id = state.users.insert(&user).await.unwrap();
    user.id = Some(id);
    user
}

pub async fn seed_whitelist_user(state: &AppState, email: &str, allowed_ips: &[&str]) -> User {
    let mut user = User::new(email, password::hash(PASSWORD).unwrap(), Vec::new());
    user.whitelist_only = true;
    user.allowed_ips = allowed_ips.iter().map(|s| s.to_string()).collect();
    let id = state.users.insert(&user).await.unwrap();
    user.id = Some(id);
    user
}

pub async fn seed_admin(state: &AppState, email: &str) -> User {
    let mut user = User::new(
        email,
        password::hash(PASSWORD).unwrap(),
        vec!["admin".to_string()],
    );
    let id = state.users.insert(&user).await.unwrap();
    user.id = Some(id);
    user
}

pub async fn activate_user(db: &Database, email: &str) {
    db.collection::<mongodb::bson::Document>("users")
        .update_one(
            doc! { "email": email.trim().to_lowercase() },
            doc! { "$set": { "status": "active" } },
        )
        .await
        .unwrap();
}

pub async fn seed_role(state: &AppState, name: &str) {
    use ch_api_authenticator::domain::role::{Portal, Role};
    let role = Role::sub_role(name, Portal::Admin);
    state.roles.insert(&role).await.unwrap();
}

pub fn roles(entries: &[(&str, &str)]) -> HashMap<String, Vec<String>> {
    entries
        .iter()
        .map(|(portal, role)| (portal.to_string(), vec![role.to_string()]))
        .collect()
}

pub struct TestResponse {
    pub status: StatusCode,

    pub set_cookie: Option<String>,

    pub set_cookies: Vec<String>,
    pub correlation_id: Option<String>,
    pub body: serde_json::Value,
}

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

pub async fn get(app: Router, path: &str, headers: &[(&str, &str)]) -> TestResponse {
    let mut request = Request::get(path);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    send(app, request.body(Body::empty()).unwrap()).await
}

pub fn with_connect_info(mut request: Request<Body>) -> Request<Body> {
    use axum::extract::ConnectInfo;
    use std::net::SocketAddr;
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 54321))));
    request
}

async fn send(app: Router, request: Request<Body>) -> TestResponse {
    let response = app.oneshot(with_connect_info(request)).await.unwrap();
    let status = response.status();
    let set_cookies: Vec<String> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    let set_cookie = set_cookies.first().cloned();
    let correlation_id = response
        .headers()
        .get(ch_api_authenticator::middleware::tracing::CORRELATION_HEADER)
        .map(|v| v.to_str().unwrap().to_string());
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    TestResponse {
        status,
        set_cookie,
        set_cookies,
        correlation_id,
        body,
    }
}

pub fn refresh_token_from_cookies(cookies: &[String]) -> String {
    cookies
        .iter()
        .find_map(|cookie| cookie.strip_prefix("ch_refresh="))
        .and_then(|rest| rest.split(';').next())
        .map(|value| value.to_string())
        .expect("cookie ch_refresh présent dans Set-Cookie")
}

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
