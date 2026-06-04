//! État de santé du service (US-07).
//!
//! Toujours `200` : `ok` si MongoDB répond au ping, `degraded` sinon.
//! En mode `degraded`, `/validate` reste pleinement fonctionnel (stateless) —
//! seuls register/login, qui touchent la base, sont réellement affectés.

use crate::state::AppState;
use axum::Json;
use axum::extract::State;
use mongodb::bson::doc;
use serde::Serialize;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
    pub mongodb: &'static str,
}

/// `GET /health` — accessible sans authentification.
pub async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    let mongo_up = state.db.run_command(doc! { "ping": 1 }).await.is_ok();
    if !mongo_up {
        tracing::warn!("Health check : MongoDB injoignable, service degrade");
    }
    Json(HealthResponse {
        status: if mongo_up { "ok" } else { "degraded" },
        version: env!("CARGO_PKG_VERSION"),
        mongodb: if mongo_up { "ok" } else { "down" },
    })
}
