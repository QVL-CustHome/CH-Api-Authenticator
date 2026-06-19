use crate::handlers;
use crate::middleware::tracing::correlation_and_access_log;
use crate::state::AppState;
use axum::Router;
use axum::middleware::from_fn;
use axum::routing::{delete, get, post, put};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(handlers::health::health))
        .route("/ping", get(handlers::ping::ping))
        .route("/register", post(handlers::register::register))
        .route("/login", post(handlers::login::login))
        .route("/refresh", post(handlers::session::refresh))
        .route("/logout", post(handlers::session::logout))
        .route("/validate", get(handlers::validate::validate))
        .route("/internal/users/resolve", post(handlers::internal::resolve_users))
        .route("/password/forgot", post(handlers::password::forgot))
        .route("/password/reset", post(handlers::password::reset))
        .route("/password", put(handlers::password::change))

        .route(
            "/settings/registration",
            get(handlers::settings::get_registration)
                .put(handlers::settings::update_registration),
        )

        .route(
            "/me",
            get(handlers::me::get_me).put(handlers::me::update_me),
        )

        .route("/users", get(handlers::admin::list_users))
        .route("/users/pending", get(handlers::admin::list_pending))
        .route(
            "/users/{id}",
            get(handlers::admin::get_user)
                .put(handlers::admin::update_user)
                .delete(handlers::admin::delete_user),
        )
        .route("/users/{id}/status", put(handlers::admin::update_status))
        .route(
            "/users/{id}/password",
            put(handlers::admin::update_password),
        )
        .route("/users/{id}/roles", put(handlers::admin::update_roles))

        .route("/analytics/traffic", get(handlers::analytics::traffic))
        .route(
            "/users/{id}/whitelist",
            put(handlers::admin::update_whitelist),
        )

        .route(
            "/roles",
            get(handlers::roles::list_roles).post(handlers::roles::create_role),
        )
        .route("/roles/{id}", delete(handlers::roles::delete_role))

        .layer(from_fn(correlation_and_access_log))
        .with_state(state)
}
