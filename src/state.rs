//! État partagé de l'application, injecté dans les handlers Axum.

use crate::config::Settings;
use crate::repository::users::UserRepository;
use crate::services::jwt::JwtService;
use crate::services::mailer::Mailer;
use mongodb::Database;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub settings: Arc<Settings>,
    /// Handle base : ping du health check (US-07).
    pub db: Database,
    pub users: UserRepository,
    pub jwt: Arc<JwtService>,
    /// Envoi des emails (US-16) — construit en amont (fail-fast au démarrage).
    pub mailer: Arc<Mailer>,
}

impl AppState {
    pub fn new(settings: Settings, db: Database, mailer: Mailer) -> Self {
        let jwt = Arc::new(JwtService::new(
            &settings.secrets.jwt_secret,
            settings.config.token.ttl_minutes,
        ));
        Self {
            settings: Arc::new(settings),
            users: UserRepository::new(&db),
            db,
            jwt,
            mailer: Arc::new(mailer),
        }
    }
}
