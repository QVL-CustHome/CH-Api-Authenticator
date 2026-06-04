//! État partagé de l'application, injecté dans les handlers Axum.

use crate::config::Settings;
use crate::repository::reset_tokens::ResetTokenRepository;
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
    /// Tokens one-time de réinitialisation de mot de passe (US-17/18).
    pub reset_tokens: ResetTokenRepository,
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
            reset_tokens: ResetTokenRepository::new(&db),
            db,
            jwt,
            mailer: Arc::new(mailer),
        }
    }
}
