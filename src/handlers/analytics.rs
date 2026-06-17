use crate::domain::role::Portal;
use crate::error::AppError;
use crate::middleware::auth::PortalAdmin;
use crate::state::AppState;
use axum::Json;
use axum::extract::{Query, State};
use mongodb::bson::DateTime;
use serde::{Deserialize, Serialize};

const DAY_MS: i64 = 24 * 3600 * 1000;

#[derive(Deserialize)]
pub struct TrafficQuery {
    pub period: Option<String>,
}

#[derive(Serialize)]
pub struct PortalTraffic {
    pub portal: String,
    pub connected_users: u64,
}

#[derive(Serialize)]
pub struct TrafficResponse {
    pub period: String,
    pub registrations: u64,
    pub portals: Vec<PortalTraffic>,
}

fn period_start(period: &str) -> DateTime {
    let delta = match period {
        "day" => DAY_MS,
        "month" => 30 * DAY_MS,
        "year" => 365 * DAY_MS,
        _ => 7 * DAY_MS,
    };
    DateTime::from_millis(DateTime::now().timestamp_millis() - delta)
}

fn normalize_period(raw: Option<String>) -> String {
    match raw.as_deref() {
        Some("day") => "day",
        Some("month") => "month",
        Some("year") => "year",
        _ => "week",
    }
    .to_string()
}

pub async fn traffic(
    State(state): State<AppState>,
    PortalAdmin(_admin): PortalAdmin,
    Query(query): Query<TrafficQuery>,
) -> Result<Json<TrafficResponse>, AppError> {
    let period = normalize_period(query.period);
    let since = period_start(&period);

    let registrations = state.users.count_created_since(since).await.map_err(|e| {
        tracing::error!(error = %e, "Comptage des inscriptions en échec");
        AppError::Internal
    })?;

    let counts = state
        .login_events
        .connected_users_by_portal(since)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Agrégation du trafic en échec");
            AppError::Internal
        })?;

    let portals = Portal::ALL
        .iter()
        .map(|p| {
            let name = p.role_name();
            let connected_users = counts
                .iter()
                .find(|c| c.portal == name)
                .map(|c| c.connected_users)
                .unwrap_or(0);
            PortalTraffic {
                portal: name.to_string(),
                connected_users,
            }
        })
        .collect();

    Ok(Json(TrafficResponse {
        period,
        registrations,
        portals,
    }))
}
