//! Route témoin de l'US-00 : vérifie que le serveur démarre et répond.

use axum::Json;
use serde_json::{Value, json};

pub async fn ping() -> Json<Value> {
    Json(json!({
        "service": env!("CARGO_PKG_NAME"),
        "version": env!("CARGO_PKG_VERSION"),
        "status": "pong",
    }))
}
