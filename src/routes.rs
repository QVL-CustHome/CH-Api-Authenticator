//! Déclaration du routeur Axum.
//! Couverture HTTP de bout en bout : voir la suite d'intégration `tests/api_*.rs`.

use crate::handlers;
use crate::middleware::tracing::correlation_and_access_log;
use crate::state::AppState;
use axum::Router;
use axum::middleware::from_fn;
use axum::routing::{get, post};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/ping", get(handlers::ping::ping))
        .route("/register", post(handlers::register::register))
        .route("/login", post(handlers::login::login))
        .route("/validate", get(handlers::validate::validate))
        // US-06 : correlation id + log d'accès sur toutes les routes.
        .layer(from_fn(correlation_and_access_log))
        .with_state(state)
}
