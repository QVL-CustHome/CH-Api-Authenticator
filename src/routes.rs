//! Déclaration du routeur Axum.
//! Couverture HTTP de bout en bout : voir la suite d'intégration `tests/api_*.rs`.

use crate::handlers;
use crate::state::AppState;
use axum::Router;
use axum::routing::{get, post};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/ping", get(handlers::ping::ping))
        .route("/register", post(handlers::register::register))
        .route("/login", post(handlers::login::login))
        .route("/validate", get(handlers::validate::validate))
        .with_state(state)
}
