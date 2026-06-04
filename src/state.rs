//! État partagé de l'application, injecté dans les handlers Axum.

use crate::config::Settings;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    // Lu par les handlers à partir de US-02 (config registration, secrets JWT…).
    #[allow(dead_code)]
    pub settings: Arc<Settings>,
}

impl AppState {
    pub fn new(settings: Settings) -> Self {
        Self {
            settings: Arc::new(settings),
        }
    }
}
