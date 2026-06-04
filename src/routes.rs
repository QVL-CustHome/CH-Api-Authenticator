//! Déclaration du routeur Axum.

use crate::handlers;
use crate::state::AppState;
use axum::Router;
use axum::routing::{get, post};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/ping", get(handlers::ping::ping))
        .route("/register", post(handlers::register::register))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, RegistrationConfig, Secrets, ServerConfig, Settings, TokenConfig};
    use crate::repository::users::UserRepository;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    /// Repository sur client lazy : aucune connexion tant qu'aucune requête DB n'est émise.
    fn test_repository() -> UserRepository {
        let options = mongodb::options::ClientOptions::builder()
            .hosts(vec![mongodb::options::ServerAddress::Tcp {
                host: "localhost".to_string(),
                port: Some(27017),
            }])
            .build();
        let client = mongodb::Client::with_options(options).unwrap();
        UserRepository::new(&client.database("ch_auth_test_routes"))
    }

    fn test_state() -> AppState {
        let settings = Settings {
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
                jwt_secret: "un-secret-de-test-suffisamment-long!!!!!".to_string(),
                mongo_uri: "mongodb://localhost:27017/test".to_string(),
                admin_email: None,
                admin_password: None,
            },
        };
        AppState::new(settings, test_repository())
    }

    #[tokio::test]
    async fn ping_repond_200_avec_version() {
        let app = router(test_state());
        let response = app
            .oneshot(Request::get("/ping").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["service"], "ch-api-authenticator");
        assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    async fn route_inconnue_repond_404() {
        let app = router(test_state());
        let response = app
            .oneshot(Request::get("/inconnue").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
