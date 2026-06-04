//! État partagé de l'application, injecté dans les handlers Axum.

use crate::config::Settings;
use crate::repository::users::UserRepository;
use crate::services::jwt::JwtService;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub settings: Arc<Settings>,
    pub users: UserRepository,
    pub jwt: Arc<JwtService>,
}

impl AppState {
    pub fn new(settings: Settings, users: UserRepository) -> Self {
        let jwt = Arc::new(JwtService::new(
            &settings.secrets.jwt_secret,
            settings.config.token.ttl_minutes,
        ));
        Self {
            settings: Arc::new(settings),
            users,
            jwt,
        }
    }
}
