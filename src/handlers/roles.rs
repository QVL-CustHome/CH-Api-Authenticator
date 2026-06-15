use crate::domain::role::{Portal, Role, RoleKind};
use crate::error::AppError;
use crate::middleware::auth::PortalAdmin;
use crate::repository::roles::RoleError;
use crate::state::AppState;
use crate::validation;
use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Serialize)]
pub struct RoleResponse {
    pub id: String,
    pub name: String,
    pub portal: Portal,
    pub kind: RoleKind,
    pub created_at: String,
}

fn role_response(role: Role) -> RoleResponse {
    RoleResponse {
        id: role.id.map(|id| id.to_hex()).unwrap_or_default(),
        name: role.name,
        portal: role.portal,
        kind: role.kind,
        created_at: role.created_at.try_to_rfc3339_string().unwrap_or_default(),
    }
}

pub async fn list_roles(
    State(state): State<AppState>,
    PortalAdmin(_admin): PortalAdmin,
) -> Result<Json<Vec<RoleResponse>>, AppError> {
    let roles = state.roles.list().await.map_err(|e| {
        tracing::error!(error = %e, "Liste des rôles en échec");
        AppError::Internal
    })?;
    Ok(Json(roles.into_iter().map(role_response).collect()))
}

#[derive(Deserialize, Validate)]
pub struct CreateRoleRequest {
    #[validate(length(min = 1, message = "le nom du rôle est requis"))]
    pub name: String,
    pub portal: Portal,
}

pub async fn create_role(
    State(state): State<AppState>,
    PortalAdmin(admin): PortalAdmin,
    payload: Result<Json<CreateRoleRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<RoleResponse>), AppError> {
    let Json(request) = payload?;
    validation::check(&request)?;
    if request.name.trim().is_empty() {
        return Err(AppError::Validation(
            "le nom du rôle est requis".to_string(),
        ));
    }

    let role = Role::sub_role(&request.name, request.portal);
    match state.roles.insert(&role).await {
        Ok(id) => {
            tracing::info!(admin_id = %admin.sub, name = %role.name, "Admin : rôle créé");
            let mut created = role;
            created.id = Some(id);
            Ok((StatusCode::CREATED, Json(role_response(created))))
        }
        Err(RoleError::Duplicate) => Err(AppError::Conflict("rôle déjà défini")),
        Err(RoleError::Database(e)) => {
            tracing::error!(error = %e, "Création du rôle en échec");
            Err(AppError::Internal)
        }
    }
}

pub async fn delete_role(
    State(state): State<AppState>,
    PortalAdmin(admin): PortalAdmin,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let role_id = ObjectId::parse_str(&id).map_err(|_| AppError::NotFound("rôle inconnu"))?;
    let role = state
        .roles
        .find_by_id(role_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Lecture du rôle en échec");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("rôle inconnu"))?;
    if role.is_portal_role() {
        return Err(AppError::Forbidden(
            "un rôle portail ne peut pas être supprimé",
        ));
    }

    let deleted = state.roles.delete(role_id).await.map_err(|e| {
        tracing::error!(error = %e, "Suppression du rôle en échec");
        AppError::Internal
    })?;
    if !deleted {
        return Err(AppError::NotFound("rôle inconnu"));
    }
    tracing::info!(admin_id = %admin.sub, role_id = %role_id, "Admin : rôle supprimé");
    Ok(StatusCode::NO_CONTENT)
}
