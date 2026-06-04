//! État partagé de l'application, injecté dans les handlers Axum.

use crate::config::Settings;
use crate::repository::users::UserRepository;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    // Lus par les handlers à partir de US-02 (config registration, secrets JWT…).
    #[allow(dead_code)]
    pub settings: Arc<Settings>,
    #[allow(dead_code)]
    pub users: UserRepository,
}

impl AppState {
    pub fn new(settings: Settings, users: UserRepository) -> Self {
        Self {
            settings: Arc::new(settings),
            users,
        }
    }
}
