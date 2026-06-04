//! Corrélation des logs et log d'accès (US-06).
//!
//! Le `X-Correlation-ID` généré par la Gateway est attaché — via un span
//! `tracing` — à TOUTES les lignes de log émises pendant la requête, et
//! renvoyé en écho dans la réponse. Un identifiant est généré si le header
//! est absent (appel direct, hors Gateway).

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;
use std::time::Instant;
use tracing::Instrument;

/// Même header que la Gateway (`CorrelationHeader` côté Go).
pub const CORRELATION_HEADER: &str = "x-correlation-id";

/// Middleware appliqué à toutes les routes.
pub async fn correlation_and_access_log(request: Request, next: Next) -> Response {
    let correlation_id = request
        .headers()
        .get(CORRELATION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let start = Instant::now();

    // Toutes les lignes de log émises dans ce span portent le correlation_id.
    let span = tracing::info_span!("requete", correlation_id = %correlation_id);

    async move {
        let mut response = next.run(request).await;

        // US-06 : log d'accès par requête.
        tracing::info!(
            method = %method,
            path = %path,
            status = response.status().as_u16(),
            duration_ms = start.elapsed().as_millis() as u64,
            "acces"
        );

        // Écho du correlation id pour le suivi côté client.
        if let Ok(value) = HeaderValue::from_str(&correlation_id) {
            response.headers_mut().insert(CORRELATION_HEADER, value);
        }
        response
    }
    .instrument(span)
    .await
}
