//! Connexion : vérification des identifiants et émission du JWT (US-03).

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

/// IP client réelle, transmise par la Gateway (logique trusted_proxies, US-10 côté Gateway).
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

/// Hash factice vérifié quand l'email est inconnu, pour que la durée de
/// réponse ne révèle pas l'existence du compte (anti-énumération par timing).
static DUMMY_HASH: LazyLock<String> =
    LazyLock::new(|| password::hash("dummy-timing-equalizer").expect("hash factice"));

/// `POST /login` → `200 {access_token, token_type, expires_in}` + cookie HttpOnly.
///
/// Anti-énumération : email inconnu et mot de passe erroné produisent
/// EXACTEMENT la même réponse `401` (US-03), et la whitelist KO aussi (US-04).
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
        tracing::error!(error = %e, "Émission du token en échec");
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

/// IP client depuis le header `X-Client-IP` (illisible ou absent → `None`).
fn client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get(CLIENT_IP_HEADER)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Cookie HttpOnly lu par la Gateway (US-11 côté Gateway).
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

#[cfg(test)]
mod tests {
    use crate::config::{Config, RegistrationConfig, Secrets, ServerConfig, Settings, TokenConfig};
    use crate::domain::user::User;
    use crate::repository::users::UserRepository;
    use crate::routes::router;
    use crate::services::password;
    use crate::state::AppState;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use http_body_util::BodyExt;
    use mongodb::Database;
    use mongodb::bson::oid::ObjectId;
    use std::collections::HashMap;
    use tower::ServiceExt;

    const JWT_SECRET: &str = "un-secret-de-test-suffisamment-long!!!!!";

    async fn test_db() -> Database {
        let client = mongodb::Client::with_uri_str("mongodb://localhost:27017")
            .await
            .expect("MongoDB locale requise pour les tests d'intégration");
        client.database(&format!("ch_auth_test_{}", ObjectId::new()))
    }

    async fn test_state(db: &Database, cookie_secure: bool) -> AppState {
        let users = UserRepository::new(db);
        users.ensure_indexes().await.unwrap();
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
                    registration: RegistrationConfig::default(),
                },
                secrets: Secrets {
                    jwt_secret: JWT_SECRET.to_string(),
                    mongo_uri: "mongodb://localhost:27017/test".to_string(),
                    admin_email: None,
                    admin_password: None,
                },
            },
            users,
        )
    }

    async fn seed_user(state: &AppState) {
        let user = User::new(
            "martin@test.fr",
            password::hash("bon-mot-de-passe").unwrap(),
            HashMap::from([("portail_a".to_string(), "admin".to_string())]),
        );
        state.users.insert(&user).await.unwrap();
    }

    async fn seed_whitelist_user(state: &AppState, allowed_ips: &[&str]) {
        let mut user = User::new(
            "secure@test.fr",
            password::hash("bon-mot-de-passe").unwrap(),
            HashMap::new(),
        );
        user.whitelist_only = true;
        user.allowed_ips = allowed_ips.iter().map(|s| s.to_string()).collect();
        state.users.insert(&user).await.unwrap();
    }

    async fn post_login(
        state: AppState,
        body: &str,
    ) -> (StatusCode, Option<String>, serde_json::Value) {
        post_login_from_ip(state, body, None).await
    }

    async fn post_login_from_ip(
        state: AppState,
        body: &str,
        client_ip: Option<&str>,
    ) -> (StatusCode, Option<String>, serde_json::Value) {
        let mut request = Request::post("/login").header(header::CONTENT_TYPE, "application/json");
        if let Some(ip) = client_ip {
            request = request.header(super::CLIENT_IP_HEADER, ip);
        }
        let response = router(state)
            .oneshot(request.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .map(|v| v.to_str().unwrap().to_string());
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, cookie, json)
    }

    #[tokio::test]
    async fn login_valide_200_token_et_cookie() {
        let db = test_db().await;
        let state = test_state(&db, false).await;
        seed_user(&state).await;

        let (status, cookie, body) = post_login(
            state.clone(),
            r#"{"email": "Martin@Test.FR", "password": "bon-mot-de-passe"}"#,
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["token_type"], "Bearer");
        assert_eq!(body["expires_in"], 15 * 60);

        // Le token se valide et porte les bons claims.
        let claims = state
            .jwt
            .validate(body["access_token"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            claims.roles.get("portail_a").map(String::as_str),
            Some("admin")
        );
        assert!(!claims.super_admin);
        assert_eq!(claims.ip, None);

        // Cookie HttpOnly posé, sans Secure (cookie_secure = false en test).
        let cookie = cookie.expect("Set-Cookie présent");
        assert!(cookie.starts_with("ch_token="));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("Max-Age=900"));
        assert!(!cookie.contains("Secure"));

        db.drop().await.unwrap();
    }

    #[tokio::test]
    async fn cookie_secure_quand_configure() {
        let db = test_db().await;
        let state = test_state(&db, true).await;
        seed_user(&state).await;

        let (_, cookie, _) = post_login(
            state,
            r#"{"email": "martin@test.fr", "password": "bon-mot-de-passe"}"#,
        )
        .await;
        assert!(cookie.unwrap().contains("; Secure"));

        db.drop().await.unwrap();
    }

    #[tokio::test]
    async fn reponse_401_strictement_identique_email_inconnu_ou_mdp_faux() {
        let db = test_db().await;
        let state = test_state(&db, false).await;
        seed_user(&state).await;

        let (status_inconnu, cookie_inconnu, body_inconnu) = post_login(
            state.clone(),
            r#"{"email": "inconnu@test.fr", "password": "peu-importe"}"#,
        )
        .await;
        let (status_mdp, cookie_mdp, body_mdp) = post_login(
            state,
            r#"{"email": "martin@test.fr", "password": "mauvais-mot-de-passe"}"#,
        )
        .await;

        // Anti-énumération : statut, body et absence de cookie identiques.
        assert_eq!(status_inconnu, StatusCode::UNAUTHORIZED);
        assert_eq!(status_mdp, StatusCode::UNAUTHORIZED);
        assert_eq!(body_inconnu, body_mdp);
        assert_eq!(cookie_inconnu, None);
        assert_eq!(cookie_mdp, None);

        db.drop().await.unwrap();
    }

    const WHITELIST_BODY: &str = r#"{"email": "secure@test.fr", "password": "bon-mot-de-passe"}"#;

    #[tokio::test]
    async fn whitelist_ip_exacte_200_avec_claim_ip() {
        let db = test_db().await;
        let state = test_state(&db, false).await;
        seed_whitelist_user(&state, &["10.1.2.3", "192.168.0.0/16"]).await;

        let (status, _, body) =
            post_login_from_ip(state.clone(), WHITELIST_BODY, Some("10.1.2.3")).await;

        assert_eq!(status, StatusCode::OK);
        let claims = state
            .jwt
            .validate(body["access_token"].as_str().unwrap())
            .unwrap();
        assert_eq!(claims.ip.as_deref(), Some("10.1.2.3"));

        db.drop().await.unwrap();
    }

    #[tokio::test]
    async fn whitelist_ip_dans_cidr_200() {
        let db = test_db().await;
        let state = test_state(&db, false).await;
        seed_whitelist_user(&state, &["10.1.2.3", "192.168.0.0/16"]).await;

        let (status, _, body) =
            post_login_from_ip(state.clone(), WHITELIST_BODY, Some("192.168.42.7")).await;

        assert_eq!(status, StatusCode::OK);
        let claims = state
            .jwt
            .validate(body["access_token"].as_str().unwrap())
            .unwrap();
        assert_eq!(claims.ip.as_deref(), Some("192.168.42.7"));

        db.drop().await.unwrap();
    }

    #[tokio::test]
    async fn whitelist_ip_hors_liste_ou_absente_401_generique() {
        let db = test_db().await;
        let state = test_state(&db, false).await;
        seed_whitelist_user(&state, &["10.1.2.3"]).await;

        // IP hors liste et header absent → même 401 qu'un mauvais mot de passe.
        let (status_hors, _, body_hors) =
            post_login_from_ip(state.clone(), WHITELIST_BODY, Some("8.8.8.8")).await;
        let (status_sans, _, body_sans) =
            post_login_from_ip(state.clone(), WHITELIST_BODY, None).await;
        let (status_mdp, _, body_mdp) = post_login_from_ip(
            state,
            r#"{"email": "secure@test.fr", "password": "mauvais"}"#,
            Some("10.1.2.3"),
        )
        .await;

        assert_eq!(status_hors, StatusCode::UNAUTHORIZED);
        assert_eq!(status_sans, StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_hors, body_mdp,
            "whitelist KO indistinguable d'un mauvais mdp"
        );
        assert_eq!(body_sans, body_mdp);
        assert_eq!(status_mdp, StatusCode::UNAUTHORIZED);

        db.drop().await.unwrap();
    }

    #[tokio::test]
    async fn user_sans_whitelist_non_impacte() {
        let db = test_db().await;
        let state = test_state(&db, false).await;
        seed_user(&state).await;

        // Sans header X-Client-IP : login OK et aucun claim ip.
        let (status, _, body) = post_login(
            state.clone(),
            r#"{"email": "martin@test.fr", "password": "bon-mot-de-passe"}"#,
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let claims = state
            .jwt
            .validate(body["access_token"].as_str().unwrap())
            .unwrap();
        assert_eq!(claims.ip, None);

        db.drop().await.unwrap();
    }

    #[tokio::test]
    async fn payload_invalide_400() {
        let db = test_db().await;
        let state = test_state(&db, false).await;

        let (status, _, error) = post_login(state, "pas du json").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(error["error"], "bad_request");

        db.drop().await.unwrap();
    }
}
