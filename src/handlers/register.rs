//! Inscription d'un nouveau compte (US-02).

use crate::domain::user::User;
use crate::error::AppError;
use crate::repository::users::RepositoryError;
use crate::services::password;
use crate::state::AppState;
use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::json;
use validator::Validate;

/// Taille minimale du mot de passe.
const MIN_PASSWORD_CHARS: u64 = 8;

// Pas de derive Debug : le mot de passe ne doit jamais fuiter dans les logs.
#[derive(Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(email(message = "format d'email invalide"))]
    pub email: String,
    #[validate(length(
        min = "MIN_PASSWORD_CHARS",
        message = "mot de passe trop court (minimum 8 caractères)"
    ))]
    pub password: String,
}

/// `POST /register` → `201 {user_id}` | `409` email déjà utilisé | `400` payload invalide.
///
/// Les rôles ne sont JAMAIS acceptés depuis le body : ils proviennent de
/// `registration.default_roles` (vide par défaut, attribution via super-admin au sprint 2).
pub async fn register(
    State(state): State<AppState>,
    payload: Result<Json<RegisterRequest>, JsonRejection>,
) -> Result<impl IntoResponse, AppError> {
    // JSON absent/malformé/champs manquants → 400 (et non 422, contrat US-02).
    let Json(request) = payload.map_err(|e| AppError::Validation(e.body_text()))?;

    request
        .validate()
        .map_err(|e| AppError::Validation(format_validation_errors(&e)))?;

    let password_hash = password::hash(&request.password).map_err(|_| AppError::Internal)?;
    let user = User::new(
        &request.email,
        password_hash,
        state.settings.config.registration.default_roles.clone(),
    );

    match state.users.insert(&user).await {
        Ok(id) => Ok((StatusCode::CREATED, Json(json!({ "user_id": id.to_hex() })))),
        Err(RepositoryError::DuplicateEmail) => Err(AppError::Conflict("email déjà utilisé")),
        Err(RepositoryError::Database(e)) => {
            tracing::error!(error = %e, "Insertion utilisateur en échec");
            Err(AppError::Internal)
        }
    }
}

fn format_validation_errors(errors: &validator::ValidationErrors) -> String {
    errors
        .field_errors()
        .values()
        .flat_map(|field_errors| field_errors.iter())
        .map(|e| e.message.as_deref().unwrap_or("champ invalide").to_string())
        .collect::<Vec<_>>()
        .join(" ; ")
}

#[cfg(test)]
mod tests {
    use crate::config::{Config, RegistrationConfig, Secrets, ServerConfig, Settings, TokenConfig};
    use crate::repository::users::UserRepository;
    use crate::routes::router;
    use crate::state::AppState;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use http_body_util::BodyExt;
    use mongodb::Database;
    use mongodb::bson::oid::ObjectId;
    use std::collections::HashMap;
    use tower::ServiceExt;

    /// Base jetable sur la MongoDB locale, supprimée en fin de test.
    async fn test_db() -> Database {
        let client = mongodb::Client::with_uri_str("mongodb://localhost:27017")
            .await
            .expect("MongoDB locale requise pour les tests d'intégration");
        client.database(&format!("ch_auth_test_{}", ObjectId::new()))
    }

    async fn test_state(db: &Database, default_roles: HashMap<String, String>) -> AppState {
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
                        cookie_secure: false,
                    },
                    registration: RegistrationConfig { default_roles },
                },
                secrets: Secrets {
                    jwt_secret: "un-secret-de-test-suffisamment-long!!!!!".to_string(),
                    mongo_uri: "mongodb://localhost:27017/test".to_string(),
                    admin_email: None,
                    admin_password: None,
                },
            },
            users,
        )
    }

    async fn post_register(state: AppState, body: &str) -> (StatusCode, serde_json::Value) {
        let response = router(state)
            .oneshot(
                Request::post("/register")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    #[tokio::test]
    async fn inscription_valide_201_avec_hash_et_roles_par_defaut() {
        let db = test_db().await;
        let roles = HashMap::from([("portail_test".to_string(), "user".to_string())]);
        let state = test_state(&db, roles).await;

        let (status, body) = post_register(
            state.clone(),
            r#"{"email": "Nouveau@Test.FR", "password": "motdepasse"}"#,
        )
        .await;

        assert_eq!(status, StatusCode::CREATED);
        assert!(body["user_id"].is_string());

        // Vérifications en base : email normalisé, hash Argon2id, rôles de la config.
        let stored = state
            .users
            .find_by_email("nouveau@test.fr")
            .await
            .unwrap()
            .expect("utilisateur en base");
        assert!(stored.password_hash.starts_with("$argon2id$"));
        assert_eq!(
            stored.roles.get("portail_test").map(String::as_str),
            Some("user")
        );
        assert!(!stored.is_super_admin);

        db.drop().await.unwrap();
    }

    #[tokio::test]
    async fn roles_du_body_ignores() {
        let db = test_db().await;
        let state = test_state(&db, HashMap::new()).await;

        // Tentative d'escalade : roles/is_super_admin dans le body → champs inconnus ignorés.
        let (status, _) = post_register(
            state.clone(),
            r#"{"email": "pirate@test.fr", "password": "motdepasse", "roles": {"portail": "admin"}, "is_super_admin": true}"#,
        )
        .await;

        assert_eq!(status, StatusCode::CREATED);
        let stored = state
            .users
            .find_by_email("pirate@test.fr")
            .await
            .unwrap()
            .unwrap();
        assert!(stored.roles.is_empty());
        assert!(!stored.is_super_admin);

        db.drop().await.unwrap();
    }

    #[tokio::test]
    async fn email_deja_utilise_409() {
        let db = test_db().await;
        let state = test_state(&db, HashMap::new()).await;

        let body = r#"{"email": "double@test.fr", "password": "motdepasse"}"#;
        let (first, _) = post_register(state.clone(), body).await;
        assert_eq!(first, StatusCode::CREATED);

        let (second, error) = post_register(state, body).await;
        assert_eq!(second, StatusCode::CONFLICT);
        assert_eq!(error["error"], "conflict");

        db.drop().await.unwrap();
    }

    #[tokio::test]
    async fn payloads_invalides_400() {
        let db = test_db().await;
        let state = test_state(&db, HashMap::new()).await;

        for body in [
            r#"{"email": "pas-un-email", "password": "motdepasse"}"#, // email invalide
            r#"{"email": "ok@test.fr", "password": "court"}"#,        // mdp < 8
            r#"{"email": "ok@test.fr"}"#,                             // champ manquant
            "pas du json",                                            // JSON malformé
        ] {
            let (status, error) = post_register(state.clone(), body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "payload : {body}");
            assert_eq!(error["error"], "bad_request");
        }

        db.drop().await.unwrap();
    }
}
