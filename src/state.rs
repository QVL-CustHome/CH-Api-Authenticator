//! État partagé de l'application, injecté dans les handlers Axum.

use crate::config::Settings;
use crate::repository::users::UserRepository;
use crate::services::jwt::JwtService;
use mongodb::Database;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub settings: Arc<Settings>,
    /// Handle base : ping du health check (US-07).
    pub db: Database,
    pub users: UserRepository,
    pub jwt: Arc<JwtService>,
}

impl AppState {
    pub fn new(settings: Settings, db: Database) -> Self {
        let jwt = Arc::new(JwtService::new(
            &settings.secrets.jwt_secret,
            settings.config.token.ttl_minutes,
        ));
        Self {
            settings: Arc::new(settings),
            users: UserRepository::new(&db),
            db,
            jwt,
        }
    }
}
