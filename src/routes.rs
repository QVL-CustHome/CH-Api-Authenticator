//! Déclaration du routeur Axum.
//! Couverture HTTP de bout en bout : voir la suite d'intégration `tests/api_*.rs`.

use crate::handlers;
use crate::middleware::tracing::correlation_and_access_log;
use crate::state::AppState;
use axum::Router;
use axum::middleware::from_fn;
use axum::routing::{get, post, put};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(handlers::health::health))
        .route("/ping", get(handlers::ping::ping))
        .route("/register", post(handlers::register::register))
        .route("/login", post(handlers::login::login))
        .route("/refresh", post(handlers::session::refresh))
        .route("/logout", post(handlers::session::logout))
        .route("/validate", get(handlers::validate::validate))
        .route("/password/forgot", post(handlers::password::forgot))
        .route("/password/reset", post(handlers::password::reset))
        .route("/password", put(handlers::password::change))
        // Endpoints protégés par l'auth interne (US-13).
        .route(
            "/me",
            get(handlers::me::get_me).put(handlers::me::update_me),
        )
        // US-06 : correlation id + log d'accès sur toutes les routes.
        .layer(from_fn(correlation_and_access_log))
        .with_state(state)
}
