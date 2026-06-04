//! Connexion : vérification des identifiants et émission du JWT (US-03).

use crate::error::AppError;
use crate::services::password;
use crate::state::AppState;
use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::header;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

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

    let access_token = state.jwt.issue(&user, None).map_err(|e| {
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

    async fn post_login(
        state: AppState,
        body: &str,
    ) -> (StatusCode, Option<String>, serde_json::Value) {
        let response = router(state)
            .oneshot(
                Request::post("/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
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
