use crate::domain::user::AccountStatus;
use crate::error::AppError;
use crate::handlers::me::{MeResponse, profile};
use crate::middleware::auth::PortalAdmin;
use crate::repository::users::RepositoryError;
use crate::services::{password, whitelist};
use crate::state::AppState;
use crate::validation;
use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use validator::{Validate, ValidationError};

fn validate_role_names(roles: &[String]) -> Result<(), ValidationError> {
    if roles.iter().any(|role| role.trim().is_empty()) {
        let mut error = ValidationError::new("role_empty");
        error.message = Some(Cow::Borrowed("les rôles ne peuvent pas être vides"));
        return Err(error);
    }
    Ok(())
}

fn validate_allowed_ips(ips: &[String]) -> Result<(), ValidationError> {
    if let Err(invalid) = whitelist::validate_entries(ips) {
        let mut error = ValidationError::new("allowed_ips");
        error.message = Some(Cow::Owned(format!(
            "allowed_ips contient une entrée invalide : {invalid} (IP ou CIDR attendu)"
        )));
        return Err(error);
    }
    Ok(())
}

const DEFAULT_LIMIT: i64 = 20;
const MAX_LIMIT: i64 = 100;

#[derive(Deserialize)]
pub struct ListQuery {
    pub page: Option<u64>,
    pub limit: Option<i64>,

    pub email: Option<String>,

    pub status: Option<String>,
}

#[derive(Serialize)]
pub struct UserListResponse {
    pub users: Vec<MeResponse>,
    pub page: u64,
    pub limit: i64,
    pub total: u64,
}

struct Pagination {
    page: u64,
    limit: i64,
    skip: u64,
}

fn paginate(page: Option<u64>, limit: Option<i64>) -> Pagination {
    let page = page.unwrap_or(1).max(1);
    let limit = limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let skip = (page - 1) * limit as u64;
    Pagination { page, limit, skip }
}

async fn paginated_users(
    state: &AppState,
    pagination: Pagination,
    email: Option<&str>,
    status: Option<AccountStatus>,
    failure_context: &'static str,
) -> Result<Json<UserListResponse>, AppError> {
    let (users, total) = state
        .users
        .list(pagination.skip, pagination.limit, email, status)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "{}", failure_context);
            AppError::Internal
        })?;

    Ok(Json(UserListResponse {
        users: users.into_iter().map(profile).collect(),
        page: pagination.page,
        limit: pagination.limit,
        total,
    }))
}

pub async fn list_users(
    State(state): State<AppState>,
    PortalAdmin(_admin): PortalAdmin,
    Query(query): Query<ListQuery>,
) -> Result<Json<UserListResponse>, AppError> {
    let status = query.status.as_deref().map(parse_status).transpose()?;
    paginated_users(
        &state,
        paginate(query.page, query.limit),
        query.email.as_deref(),
        status,
        "Liste des utilisateurs en échec",
    )
    .await
}

pub async fn list_pending(
    State(state): State<AppState>,
    PortalAdmin(_admin): PortalAdmin,
    Query(query): Query<ListQuery>,
) -> Result<Json<UserListResponse>, AppError> {
    paginated_users(
        &state,
        paginate(query.page, query.limit),
        None,
        Some(AccountStatus::PendingValidation),
        "Liste des comptes en attente en échec",
    )
    .await
}

#[derive(Deserialize, Validate)]
pub struct UpdateRolesRequest {
    #[validate(custom(function = "validate_role_names"))]
    pub roles: Vec<String>,
}

pub async fn update_roles(
    State(state): State<AppState>,
    PortalAdmin(admin): PortalAdmin,
    Path(id): Path<String>,
    payload: Result<Json<UpdateRolesRequest>, JsonRejection>,
) -> Result<Json<MeResponse>, AppError> {
    let Json(request) = payload?;
    validation::check(&request)?;

    for role in &request.roles {
        let exists = state.roles.exists(role).await.map_err(|e| {
            tracing::error!(error = %e, "Vérification du rôle en échec");
            AppError::Internal
        })?;
        if !exists {
            return Err(AppError::Validation(format!(
                "rôle inexistant dans le catalogue : {role}"
            )));
        }
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

    tracing::info!(
        admin_id = %admin.sub,
        target_id = %user_id,
        roles = ?request.roles,
        "Admin : rôles remplacés"
    );

    load_profile(&state, user_id).await
}

#[derive(Deserialize, Validate)]
pub struct UpdateWhitelistRequest {
    pub whitelist_only: bool,
    #[serde(default)]
    #[validate(custom(function = "validate_allowed_ips"))]
    pub allowed_ips: Vec<String>,
}

pub async fn update_whitelist(
    State(state): State<AppState>,
    PortalAdmin(admin): PortalAdmin,
    Path(id): Path<String>,
    payload: Result<Json<UpdateWhitelistRequest>, JsonRejection>,
) -> Result<Json<MeResponse>, AppError> {
    let Json(request) = payload?;
    validation::check(&request)?;

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

#[derive(Deserialize, Validate)]
pub struct UpdateStatusRequest {
    pub status: AccountStatus,
}

pub async fn update_status(
    State(state): State<AppState>,
    PortalAdmin(admin): PortalAdmin,
    Path(id): Path<String>,
    payload: Result<Json<UpdateStatusRequest>, JsonRejection>,
) -> Result<Json<MeResponse>, AppError> {
    let Json(request) = payload?;
    validation::check(&request)?;

    let user_id = parse_target_id(&id)?;
    let updated = state
        .users
        .update_status(user_id, request.status)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Mise à jour du statut en échec");
            AppError::Internal
        })?;
    if !updated {
        return Err(AppError::NotFound("utilisateur inconnu"));
    }

    tracing::info!(
        admin_id = %admin.sub,
        target_id = %user_id,
        status = ?request.status,
        "Admin : statut du compte modifié"
    );

    load_profile(&state, user_id).await
}

#[derive(Deserialize, Validate)]
pub struct UpdateUserRequest {
    #[validate(length(min = 1, message = "le nom est requis"))]
    pub name: String,
    #[validate(email(message = "format d'email invalide"))]
    pub email: String,
}

pub async fn update_user(
    State(state): State<AppState>,
    PortalAdmin(admin): PortalAdmin,
    Path(id): Path<String>,
    payload: Result<Json<UpdateUserRequest>, JsonRejection>,
) -> Result<Json<MeResponse>, AppError> {
    let Json(request) = payload?;
    request
        .validate()
        .map_err(|_| AppError::Validation("nom ou email invalide".to_string()))?;
    if request.name.trim().is_empty() {
        return Err(AppError::Validation("le nom est requis".to_string()));
    }

    let user_id = parse_target_id(&id)?;
    let email = request.email.trim().to_lowercase();
    match state.users.update_email(user_id, &email).await {
        Ok(true) => {}
        Ok(false) => return Err(AppError::NotFound("utilisateur inconnu")),
        Err(RepositoryError::DuplicateEmail) => {
            return Err(AppError::Conflict("email déjà utilisé"));
        }
        Err(RepositoryError::Database(e)) => {
            tracing::error!(error = %e, "Mise à jour de l'email (admin) en échec");
            return Err(AppError::Internal);
        }
    }

    state
        .users
        .update_name(user_id, request.name.trim())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Mise à jour du nom (admin) en échec");
            AppError::Internal
        })?;

    tracing::info!(admin_id = %admin.sub, target_id = %user_id, "Admin : profil modifié");
    load_profile(&state, user_id).await
}

pub async fn get_user(
    State(state): State<AppState>,
    PortalAdmin(_admin): PortalAdmin,
    Path(id): Path<String>,
) -> Result<Json<MeResponse>, AppError> {
    let user_id = parse_target_id(&id)?;
    load_profile(&state, user_id).await
}

pub async fn delete_user(
    State(state): State<AppState>,
    PortalAdmin(admin): PortalAdmin,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let user_id = parse_target_id(&id)?;
    let deleted = state.users.delete(user_id).await.map_err(|e| {
        tracing::error!(error = %e, "Suppression du compte en échec");
        AppError::Internal
    })?;
    if !deleted {
        return Err(AppError::NotFound("utilisateur inconnu"));
    }

    tracing::info!(admin_id = %admin.sub, target_id = %user_id, "Admin : compte supprimé");
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, Validate)]
pub struct UpdatePasswordRequest {
    #[validate(custom(function = "crate::validation::validate_password_strength"))]
    pub password: String,
}

pub async fn update_password(
    State(state): State<AppState>,
    PortalAdmin(admin): PortalAdmin,
    Path(id): Path<String>,
    payload: Result<Json<UpdatePasswordRequest>, JsonRejection>,
) -> Result<StatusCode, AppError> {
    let Json(request) = payload?;
    validation::check(&request)?;

    let user_id = parse_target_id(&id)?;
    let hash = password::hash(&request.password).map_err(|_| AppError::Internal)?;
    let updated = state
        .users
        .update_password(user_id, &hash)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Réinitialisation du mot de passe en échec");
            AppError::Internal
        })?;
    if !updated {
        return Err(AppError::NotFound("utilisateur inconnu"));
    }

    tracing::info!(admin_id = %admin.sub, target_id = %user_id, "Admin : mot de passe réinitialisé");
    Ok(StatusCode::NO_CONTENT)
}

fn parse_status(raw: &str) -> Result<AccountStatus, AppError> {
    match raw {
        "active" => Ok(AccountStatus::Active),
        "disabled" => Ok(AccountStatus::Disabled),
        "pending_validation" | "pending" => Ok(AccountStatus::PendingValidation),
        other => Err(AppError::Validation(format!("statut inconnu : {other}"))),
    }
}

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
