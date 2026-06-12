use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;
use std::time::Instant;
use tracing::Instrument;

pub const CORRELATION_HEADER: &str = "x-correlation-id";

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

    let span = tracing::info_span!("requete", correlation_id = %correlation_id);

    async move {
        let mut response = next.run(request).await;

        tracing::info!(
            method = %method,
            path = %path,
            status = response.status().as_u16(),
            duration_ms = start.elapsed().as_millis() as u64,
            "acces"
        );

        if let Ok(value) = HeaderValue::from_str(&correlation_id) {
            response.headers_mut().insert(CORRELATION_HEADER, value);
        }
        response
    }
    .instrument(span)
    .await
}
