use crate::error::AppError;
use crate::middleware::auth::PortalAdmin;
use crate::state::AppState;
use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct RegistrationSettingResponse {
    pub enabled: bool,
}

pub async fn get_registration(
    State(state): State<AppState>,
) -> Result<Json<RegistrationSettingResponse>, AppError> {
    let enabled = state
        .settings_repo
        .registration_enabled()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Lecture du réglage d'inscription en échec");
            AppError::Internal
        })?;
    Ok(Json(RegistrationSettingResponse { enabled }))
}

#[derive(Deserialize)]
pub struct UpdateRegistrationRequest {
    pub enabled: bool,
}

pub async fn update_registration(
    State(state): State<AppState>,
    PortalAdmin(admin): PortalAdmin,
    payload: Result<Json<UpdateRegistrationRequest>, JsonRejection>,
) -> Result<Json<RegistrationSettingResponse>, AppError> {
    let Json(request) = payload?;

    state
        .settings_repo
        .set_registration_enabled(request.enabled)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Mise à jour du réglage d'inscription en échec");
            AppError::Internal
        })?;

    tracing::info!(
        admin_id = %admin.sub,
        enabled = request.enabled,
        "Admin : inscription publique modifiée"
    );

    Ok(Json(RegistrationSettingResponse {
        enabled: request.enabled,
    }))
}
