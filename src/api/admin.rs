use crate::api::auth;
use crate::db::{AuthSettings, User};
use crate::error::AppError;
use crate::pool::manager::{PoolProxy, ProxyListQuery};
use crate::AppState;
use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    username: String,
    password: String,
    name: Option<String>,
    #[serde(default)]
    can_use_relay: bool,
}

#[derive(Debug, Deserialize)]
pub struct AuthSettingsRequest {
    allow_account_login: bool,
    allow_linux_do_login: bool,
    allow_registration: bool,
    allow_new_users: bool,
}

#[derive(Debug, Deserialize)]
pub struct RelayPermissionRequest {
    allowed: bool,
}

pub async fn list_proxies(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ProxyListQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let result = state.pool.list_proxies(&query);
    let proxy_list: Vec<serde_json::Value> =
        result.proxies.iter().map(admin_proxy_to_json).collect();

    Ok(Json(json!({
        "proxies": proxy_list,
        "total": result.total,
        "page": result.page,
        "per_page": result.per_page,
    })))
}

fn admin_proxy_to_json(p: &PoolProxy) -> serde_json::Value {
    json!({
        "id": p.id,
        "subscription_id": p.subscription_id,
        "name": p.name,
        "type": p.proxy_type,
        "server": p.server,
        "port": p.port,
        "local_port": p.local_port,
        "status": p.status,
        "error_count": p.error_count,
        "quality": p.quality.as_ref().map(|q| json!({
            "ip_address": q.ip_address,
            "country": q.country,
            "ip_type": q.ip_type,
            "is_residential": q.is_residential,
            "chatgpt": q.chatgpt_accessible,
            "google": q.google_accessible,
            "risk_score": q.risk_score,
            "risk_level": q.risk_level,
        })),
    })
}

pub async fn delete_proxy(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    state.pool.remove(&id);
    state.db.delete_proxy(&id)?;
    Ok(Json(json!({ "message": "Proxy deleted" })))
}

pub async fn cleanup_proxies(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let threshold = state.config.validation.error_threshold;
    let count = state.db.cleanup_high_error_proxies(threshold)?;

    // Remove from pool too
    let all = state.pool.get_all();
    for p in &all {
        if p.error_count >= threshold {
            state.pool.remove(&p.id);
        }
    }

    Ok(Json(json!({
        "message": format!("Cleaned up {count} proxies"),
        "removed": count,
    })))
}

pub async fn trigger_validation(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let state_clone = state.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::pool::validator::validate_all(state_clone).await {
            tracing::error!("Manual validation failed: {e}");
        }
    });

    Ok(Json(json!({
        "message": "Validation started in background"
    })))
}

pub async fn trigger_quality_check(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let state_clone = state.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::quality::checker::check_all(state_clone).await {
            tracing::error!("Manual quality check failed: {e}");
        }
    });

    Ok(Json(json!({
        "message": "Quality check started in background"
    })))
}

pub async fn get_stats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let stats = state.db.get_stats()?;
    Ok(Json(stats))
}

pub async fn list_users(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let users = state.db.get_all_users()?;
    let total = users.len();
    Ok(Json(json!({
        "users": users,
        "total": total,
    })))
}

pub async fn create_user(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let settings = state.db.get_auth_settings()?;
    if !settings.allow_new_users {
        return Err(AppError::BadRequest(
            "New user creation is currently disabled".into(),
        ));
    }
    let username = normalize_username(&req.username)?;
    if state.db.get_user_by_username(&username)?.is_some() {
        return Err(AppError::BadRequest("Username already exists".into()));
    }
    let now = chrono::Utc::now().to_rfc3339();
    let user = User {
        id: uuid::Uuid::new_v4().to_string(),
        username,
        name: req.name.filter(|s| !s.trim().is_empty()),
        avatar_template: None,
        active: true,
        trust_level: 0,
        silenced: false,
        is_banned: false,
        can_use_relay: req.can_use_relay,
        api_key: uuid::Uuid::new_v4().to_string(),
        auth_provider: "account".to_string(),
        password_hash: Some(auth::hash_password(&req.password)?),
        created_at: now.clone(),
        updated_at: now,
    };
    state.db.upsert_user(&user)?;
    Ok(Json(json!({ "message": "User created", "user": user })))
}

pub async fn get_auth_settings(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(json!(state.db.get_auth_settings()?)))
}

pub async fn update_auth_settings(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AuthSettingsRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let settings = AuthSettings {
        allow_account_login: req.allow_account_login,
        allow_linux_do_login: req.allow_linux_do_login,
        allow_registration: req.allow_registration,
        allow_new_users: req.allow_new_users,
    };
    state.db.update_auth_settings(&settings)?;
    Ok(Json(
        json!({ "message": "Auth settings updated", "settings": settings }),
    ))
}

pub async fn delete_user(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    state.db.delete_user(&id)?;
    Ok(Json(json!({ "message": "User deleted" })))
}

pub async fn ban_user(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    state.db.set_user_banned(&id, true)?;
    state.auth_cache.clear();
    Ok(Json(json!({ "message": "User banned" })))
}

pub async fn unban_user(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    state.db.set_user_banned(&id, false)?;
    Ok(Json(json!({ "message": "User unbanned" })))
}

pub async fn set_user_relay_permission(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<RelayPermissionRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    state.db.set_user_relay_allowed(&id, req.allowed)?;
    state.auth_cache.clear();
    Ok(Json(json!({
        "message": "User relay permission updated",
        "allowed": req.allowed,
    })))
}

fn normalize_username(username: &str) -> Result<String, AppError> {
    let username = username.trim();
    if username.len() < 3 || username.len() > 40 {
        return Err(AppError::BadRequest(
            "Username must be 3-40 characters".into(),
        ));
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(AppError::BadRequest(
            "Username may only contain letters, numbers, _, - and .".into(),
        ));
    }
    Ok(username.to_string())
}
