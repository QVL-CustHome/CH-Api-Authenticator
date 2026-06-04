//! Déclaration du routeur Axum.

use crate::handlers;
use crate::state::AppState;
use axum::Router;
use axum::routing::get;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/ping", get(handlers::ping::ping))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, RegistrationConfig, Secrets, ServerConfig, Settings, TokenConfig};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn test_state() -> AppState {
        AppState::new(Settings {
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
        })
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
