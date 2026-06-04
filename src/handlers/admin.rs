//! Administration des comptes — réservée au super-admin (US-20).
//!
//! Chaque action est tracée avec l'identifiant de l'admin (audit léger).

use crate::error::AppError;
use crate::handlers::me::{MeResponse, profile};
use crate::middleware::auth::SuperAdmin;
use crate::services::whitelist;
use crate::state::AppState;
use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const DEFAULT_LIMIT: i64 = 20;
const MAX_LIMIT: i64 = 100;

#[derive(Deserialize)]
pub struct ListQuery {
    pub page: Option<u64>,
    pub limit: Option<i64>,
    /// Filtre par email exact (normalisé lowercase).
    pub email: Option<String>,
}

#[derive(Serialize)]
pub struct UserListResponse {
    pub users: Vec<MeResponse>,
    pub page: u64,
    pub limit: i64,
    pub total: u64,
}

/// `GET /users?page&limit&email` → liste paginée, sans `password_hash`.
pub async fn list_users(
    State(state): State<AppState>,
    SuperAdmin(_admin): SuperAdmin,
    Query(query): Query<ListQuery>,
) -> Result<Json<UserListResponse>, AppError> {
    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let skip = (page - 1) * limit as u64;

    let (users, total) = state
        .users
        .list(skip, limit, query.email.as_deref())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Liste des utilisateurs en échec");
            AppError::Internal
        })?;

    Ok(Json(UserListResponse {
        users: users.into_iter().map(profile).collect(),
        page,
        limit,
        total,
    }))
}

#[derive(Deserialize)]
pub struct UpdateRolesRequest {
    pub roles: HashMap<String, String>,
}

/// `PUT /users/{id}/roles` → remplace la map `{portail: rôle}`.
pub async fn update_roles(
    State(state): State<AppState>,
    SuperAdmin(admin): SuperAdmin,
    Path(id): Path<String>,
    payload: Result<Json<UpdateRolesRequest>, JsonRejection>,
) -> Result<Json<MeResponse>, AppError> {
    let Json(request) = payload.map_err(|e| AppError::Validation(e.body_text()))?;

    // Des clés ou rôles vides rendraient le portail injoignable au /validate.
    if request
        .roles
        .iter()
        .any(|(portal, role)| portal.trim().is_empty() || role.trim().is_empty())
    {
        return Err(AppError::Validation(
            "les portails et rôles ne peuvent pas être vides".to_string(),
        ));
    }

    let user_id = parse_target_id(&id)?;
    let updated = state
        .users
        .update_roles(user_id, &request.roles)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Mise à jour des rôles en échec");
            AppError::Internal
        })?;
    if !updated {
        return Err(AppError::NotFound("utilisateur inconnu"));
    }

    // Audit : qui a attribué quoi à qui.
    tracing::info!(
        admin_id = %admin.sub,
        target_id = %user_id,
        roles = ?request.roles,
        "Admin : rôles remplacés"
    );

    load_profile(&state, user_id).await
}

#[derive(Deserialize)]
pub struct UpdateWhitelistRequest {
    pub whitelist_only: bool,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
}

/// `PUT /users/{id}/whitelist` → active/désactive la restriction IP.
pub async fn update_whitelist(
    State(state): State<AppState>,
    SuperAdmin(admin): SuperAdmin,
    Path(id): Path<String>,
    payload: Result<Json<UpdateWhitelistRequest>, JsonRejection>,
) -> Result<Json<MeResponse>, AppError> {
    let Json(request) = payload.map_err(|e| AppError::Validation(e.body_text()))?;

    if let Err(invalid) = whitelist::validate_entries(&request.allowed_ips) {
        return Err(AppError::Validation(format!(
            "allowed_ips contient une entrée invalide : {invalid:?} (IP ou CIDR attendu)"
        )));
    }
    if request.whitelist_only && request.allowed_ips.is_empty() {
        return Err(AppError::Validation(
            "whitelist_only sans allowed_ips verrouillerait le compte définitivement".to_string(),
        ));
    }

    let user_id = parse_target_id(&id)?;
    let updated = state
        .users
        .update_whitelist(user_id, request.whitelist_only, &request.allowed_ips)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Mise à jour de la whitelist en échec");
            AppError::Internal
        })?;
    if !updated {
        return Err(AppError::NotFound("utilisateur inconnu"));
    }

    tracing::info!(
        admin_id = %admin.sub,
        target_id = %user_id,
        whitelist_only = request.whitelist_only,
        allowed_ips = ?request.allowed_ips,
        "Admin : whitelist mise à jour"
    );

    load_profile(&state, user_id).await
}

/// Un id illisible est traité comme un utilisateur inconnu (404).
fn parse_target_id(id: &str) -> Result<ObjectId, AppError> {
    ObjectId::parse_str(id).map_err(|_| AppError::NotFound("utilisateur inconnu"))
}

async fn load_profile(state: &AppState, user_id: ObjectId) -> Result<Json<MeResponse>, AppError> {
    let user = state
        .users
        .find_by_id(user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Lecture utilisateur en échec");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("utilisateur inconnu"))?;
    Ok(Json(profile(user)))
}
