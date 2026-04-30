use crate::db::User;
use crate::error::AppError;
use crate::AppState;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use base64::Engine;
use ring::{
    digest, pbkdf2,
    rand::{SecureRandom, SystemRandom},
};
use serde::Deserialize;
use serde_json::json;
use std::num::NonZeroU32;
use std::sync::Arc;

const AUTHORIZE_URL: &str = "https://connect.linux.do/oauth2/authorize";
const TOKEN_URL: &str = "https://connect.linux.do/oauth2/token";
const USERINFO_URL: &str = "https://connect.linux.do/api/user";
pub const COOKIE_NAME: &str = "zenproxy_session";
const PASSWORD_ITERATIONS: u32 = 210_000;

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Debug, Deserialize)]
struct LinuxDoUser {
    id: i64,
    username: String,
    name: Option<String>,
    avatar_template: Option<String>,
    active: Option<bool>,
    trust_level: Option<i32>,
    silenced: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct AccountAuthRequest {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    username: String,
    password: String,
    name: Option<String>,
}

pub async fn settings(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let settings = state.db.get_auth_settings()?;
    Ok(Json(json!(settings)))
}

pub async fn login(State(state): State<Arc<AppState>>) -> Response {
    if let Ok(settings) = state.db.get_auth_settings() {
        if !settings.allow_linux_do_login {
            return Json(json!({ "error": "Linux.do login is disabled" })).into_response();
        }
    }
    let client_id = &state.config.oauth.client_id;
    let redirect_uri = &state.config.oauth.redirect_uri;
    let url = format!(
        "{AUTHORIZE_URL}?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code"
    );
    Redirect::temporary(&url).into_response()
}

pub async fn account_login(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AccountAuthRequest>,
) -> Result<Response, AppError> {
    let settings = state.db.get_auth_settings()?;
    if !settings.allow_account_login {
        return Err(AppError::Unauthorized("Account login is disabled".into()));
    }
    let username = normalize_username(&req.username)?;
    let user = state
        .db
        .get_user_by_username(&username)?
        .ok_or_else(|| AppError::Unauthorized("Invalid username or password".into()))?;

    if user.is_banned {
        return Err(AppError::Unauthorized("Account banned".into()));
    }
    let password_hash = user.password_hash.as_deref().ok_or_else(|| {
        AppError::Unauthorized("Password login is not enabled for this user".into())
    })?;
    if !verify_password(&req.password, password_hash) {
        return Err(AppError::Unauthorized(
            "Invalid username or password".into(),
        ));
    }
    create_login_response(&state, &user.id)
}

pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterRequest>,
) -> Result<Response, AppError> {
    let settings = state.db.get_auth_settings()?;
    if !settings.allow_new_users {
        return Err(AppError::Unauthorized(
            "New user creation is disabled".into(),
        ));
    }
    if !settings.allow_registration {
        return Err(AppError::Unauthorized("Registration is disabled".into()));
    }
    if !settings.allow_account_login {
        return Err(AppError::Unauthorized("Account login is disabled".into()));
    }
    let username = normalize_username(&req.username)?;
    validate_password(&req.password)?;
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
        can_use_relay: false,
        api_key: uuid::Uuid::new_v4().to_string(),
        auth_provider: "account".to_string(),
        password_hash: Some(hash_password(&req.password)?),
        created_at: now.clone(),
        updated_at: now,
    };
    state.db.upsert_user(&user)?;
    create_login_response(&state, &user.id)
}

pub async fn callback(
    State(state): State<Arc<AppState>>,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, AppError> {
    let client = reqwest::Client::new();

    // Exchange code for token
    let token_resp = client
        .post(TOKEN_URL)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &query.code),
            ("client_id", &state.config.oauth.client_id),
            ("client_secret", &state.config.oauth.client_secret),
            ("redirect_uri", &state.config.oauth.redirect_uri),
        ])
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Token exchange failed: {e}")))?;

    if !token_resp.status().is_success() {
        let body = token_resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!("Token exchange error: {body}")));
    }

    let token: TokenResponse = token_resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("Token parse error: {e}")))?;

    // Fetch user info
    let user_resp = client
        .get(USERINFO_URL)
        .bearer_auth(&token.access_token)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("User info fetch failed: {e}")))?;

    if !user_resp.status().is_success() {
        let body = user_resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!("User info error: {body}")));
    }

    let ldo_user: LinuxDoUser = user_resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("User info parse error: {e}")))?;

    let trust_level = ldo_user.trust_level.unwrap_or(0);
    let min_trust = state.config.server.min_trust_level;

    if trust_level < min_trust {
        // Return an HTML error page instead of JSON for OAuth callback
        let html = format!(
            r#"<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Access Denied</title>
            <style>body{{font-family:system-ui;background:#0f1117;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}}
            .box{{background:#1a1d27;border:1px solid #2a2d3a;border-radius:16px;padding:40px;text-align:center;max-width:400px}}
            h2{{color:#ef4444;margin-bottom:12px}}a{{color:#6c63ff}}</style></head>
            <body><div class="box"><h2>Access Denied</h2>
            <p>Your trust level ({trust_level}) is below the minimum required ({min_trust}).</p>
            <p style="margin-top:16px"><a href="/">Back</a></p></div></body></html>"#
        );
        return Ok(axum::response::Html(html).into_response());
    }

    let now = chrono::Utc::now().to_rfc3339();
    let user_id = ldo_user.id.to_string();

    // Check if user exists to preserve api_key and admin-managed permissions.
    let (api_key, can_use_relay) = match state.db.get_user_by_id(&user_id)? {
        Some(existing) => {
            if existing.is_banned {
                let html = r#"<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Banned</title>
                <style>body{font-family:system-ui;background:#0f1117;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
                .box{background:#1a1d27;border:1px solid #2a2d3a;border-radius:16px;padding:40px;text-align:center;max-width:400px}
                h2{color:#ef4444;margin-bottom:12px}a{color:#6c63ff}</style></head>
                <body><div class="box"><h2>Account Banned</h2>
                <p>Your account has been banned by the administrator.</p>
                <p style="margin-top:16px"><a href="/">Back</a></p></div></body></html>"#;
                return Ok(axum::response::Html(html).into_response());
            }
            (existing.api_key, existing.can_use_relay)
        }
        None => {
            let settings = state.db.get_auth_settings()?;
            if !settings.allow_new_users {
                let html = r#"<!DOCTYPE html><html><head><meta charset="UTF-8"><title>New Users Disabled</title>
                <style>body{font-family:system-ui;background:#0f1117;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
                .box{background:#1a1d27;border:1px solid #2a2d3a;border-radius:16px;padding:40px;text-align:center;max-width:420px}
                h2{color:#ef4444;margin-bottom:12px}a{color:#6c63ff}</style></head>
                <body><div class="box"><h2>New User Creation Disabled</h2>
                <p>The administrator has temporarily paused creating new users.</p>
                <p style="margin-top:16px"><a href="/">Back</a></p></div></body></html>"#;
                return Ok(axum::response::Html(html).into_response());
            }
            (uuid::Uuid::new_v4().to_string(), false)
        }
    };

    let user = User {
        id: user_id.clone(),
        username: ldo_user.username,
        name: ldo_user.name,
        avatar_template: ldo_user.avatar_template,
        active: ldo_user.active.unwrap_or(true),
        trust_level,
        silenced: ldo_user.silenced.unwrap_or(false),
        is_banned: false,
        can_use_relay,
        api_key,
        auth_provider: "linux_do".to_string(),
        password_hash: None,
        created_at: now.clone(),
        updated_at: now,
    };

    state.db.upsert_user(&user)?;

    create_redirect_login_response(&state, &user_id)
}

pub async fn me(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let user = extract_session_user(&state, &headers).await?;
    Ok(Json(json!({
        "id": user.id,
        "username": user.username,
        "name": user.name,
        "avatar_template": user.avatar_template,
        "trust_level": user.trust_level,
        "api_key": user.api_key,
        "created_at": user.created_at,
    })))
}

pub async fn logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    if let Some(session_id) = extract_session_id(&headers) {
        state.db.delete_session(&session_id)?;
    }
    let secure = if state.config.oauth.redirect_uri.starts_with("https") {
        "; Secure"
    } else {
        ""
    };
    let cookie = format!("{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}");
    let mut response = Json(json!({ "message": "Logged out" })).into_response();
    response
        .headers_mut()
        .insert("Set-Cookie", HeaderValue::from_str(&cookie).unwrap());
    Ok(response)
}

pub async fn regenerate_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let user = extract_session_user(&state, &headers).await?;
    let new_key = state.db.regenerate_api_key(&user.id)?;
    Ok(Json(json!({ "api_key": new_key })))
}

// --- Helper functions ---

pub fn extract_session_id(headers: &HeaderMap) -> Option<String> {
    let cookie_header = headers.get("cookie")?.to_str().ok()?;
    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix(&format!("{COOKIE_NAME}=")) {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

pub async fn extract_session_user(state: &AppState, headers: &HeaderMap) -> Result<User, AppError> {
    let session_id = extract_session_id(headers)
        .ok_or_else(|| AppError::Unauthorized("No session cookie".into()))?;

    let session = state
        .db
        .get_session(&session_id)?
        .ok_or_else(|| AppError::Unauthorized("Invalid session".into()))?;

    // Check expiry
    let expires = chrono::DateTime::parse_from_rfc3339(&session.expires_at)
        .map_err(|_| AppError::Unauthorized("Invalid session expiry".into()))?;
    if chrono::Utc::now() > expires {
        state.db.delete_session(&session_id)?;
        return Err(AppError::Unauthorized("Session expired".into()));
    }

    let user = state
        .db
        .get_user_by_id(&session.user_id)?
        .ok_or_else(|| AppError::Unauthorized("User not found".into()))?;

    if user.is_banned {
        state.db.delete_user_sessions(&user.id)?;
        return Err(AppError::Unauthorized("Account banned".into()));
    }

    Ok(user)
}

pub async fn extract_api_key_user(
    state: &AppState,
    headers: &HeaderMap,
    query_api_key: Option<&str>,
) -> Result<User, AppError> {
    // Try Authorization: Bearer <api_key> header first
    let api_key = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
        .or_else(|| query_api_key.map(|s| s.to_string()));

    if let Some(key) = api_key {
        let user = state
            .db
            .get_user_by_api_key(&key)?
            .ok_or_else(|| AppError::Unauthorized("Invalid API key".into()))?;

        if user.is_banned {
            return Err(AppError::Unauthorized("Account banned".into()));
        }

        return Ok(user);
    }

    Err(AppError::Unauthorized("No API key provided".into()))
}

/// Cache TTL for auth lookups — avoids hitting DB mutex on every relay request.
const AUTH_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(60);

/// Try API key first, then session cookie. Uses in-memory cache.
pub async fn authenticate_request(
    state: &AppState,
    headers: &HeaderMap,
    query_api_key: Option<&str>,
) -> Result<User, AppError> {
    // Try API key (from header or query)
    let api_key = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
        .or_else(|| query_api_key.map(|s| s.to_string()));

    if let Some(ref key) = api_key {
        let cache_key = format!("ak:{key}");
        if let Some(user) = get_cached_user(state, &cache_key) {
            return Ok(user);
        }
        if let Ok(user) = extract_api_key_user(state, headers, query_api_key).await {
            cache_user(state, &cache_key, &user);
            return Ok(user);
        }
    }

    // Try session cookie
    if let Some(session_id) = extract_session_id(headers) {
        let cache_key = format!("ss:{session_id}");
        if let Some(user) = get_cached_user(state, &cache_key) {
            return Ok(user);
        }
        if let Ok(user) = extract_session_user(state, headers).await {
            cache_user(state, &cache_key, &user);
            return Ok(user);
        }
    }

    Err(AppError::Unauthorized(
        "Authentication required. Provide an API key or login via OAuth.".into(),
    ))
}

fn get_cached_user(state: &AppState, cache_key: &str) -> Option<User> {
    let entry = state.auth_cache.get(cache_key)?;
    let (user, expires) = entry.value();
    if tokio::time::Instant::now() < *expires {
        Some(user.clone())
    } else {
        // Don't remove here — avoids TOCTOU race where a concurrent insert
        // could be deleted. Let the periodic cleanup task handle expired entries.
        None
    }
}

fn cache_user(state: &AppState, cache_key: &str, user: &User) {
    let expires = tokio::time::Instant::now() + AUTH_CACHE_TTL;
    state
        .auth_cache
        .insert(cache_key.to_string(), (user.clone(), expires));
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

fn validate_password(password: &str) -> Result<(), AppError> {
    if password.len() < 8 {
        return Err(AppError::BadRequest(
            "Password must be at least 8 characters".into(),
        ));
    }
    if password.len() > 256 {
        return Err(AppError::BadRequest("Password is too long".into()));
    }
    Ok(())
}

pub fn hash_password(password: &str) -> Result<String, AppError> {
    validate_password(password)?;
    let rng = SystemRandom::new();
    let mut salt = [0u8; 16];
    rng.fill(&mut salt)
        .map_err(|_| AppError::Internal("Failed to generate password salt".into()))?;
    let mut hash = [0u8; digest::SHA256_OUTPUT_LEN];
    let iterations = NonZeroU32::new(PASSWORD_ITERATIONS).unwrap();
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        &salt,
        password.as_bytes(),
        &mut hash,
    );
    let b64 = base64::engine::general_purpose::STANDARD_NO_PAD;
    Ok(format!(
        "pbkdf2_sha256${PASSWORD_ITERATIONS}${}${}",
        b64.encode(salt),
        b64.encode(hash)
    ))
}

fn verify_password(password: &str, stored: &str) -> bool {
    let parts: Vec<&str> = stored.split('$').collect();
    if parts.len() != 4 || parts[0] != "pbkdf2_sha256" {
        return false;
    }
    let iterations = match parts[1].parse::<u32>().ok().and_then(NonZeroU32::new) {
        Some(value) => value,
        None => return false,
    };
    let b64 = base64::engine::general_purpose::STANDARD_NO_PAD;
    let salt = match b64.decode(parts[2]) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let hash = match b64.decode(parts[3]) {
        Ok(value) => value,
        Err(_) => return false,
    };
    pbkdf2::verify(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        &salt,
        password.as_bytes(),
        &hash,
    )
    .is_ok()
}

fn create_login_response(state: &AppState, user_id: &str) -> Result<Response, AppError> {
    let session = state.db.create_session(user_id)?;
    let secure = if state.config.oauth.redirect_uri.starts_with("https") {
        "; Secure"
    } else {
        ""
    };
    let cookie = format!(
        "{COOKIE_NAME}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800{secure}",
        session.id
    );
    let mut response = Json(json!({ "message": "Logged in" })).into_response();
    response
        .headers_mut()
        .insert("Set-Cookie", HeaderValue::from_str(&cookie).unwrap());
    Ok(response)
}

fn create_redirect_login_response(state: &AppState, user_id: &str) -> Result<Response, AppError> {
    let mut response = create_login_response(state, user_id)?;
    *response.status_mut() = axum::http::StatusCode::FOUND;
    response
        .headers_mut()
        .insert("Location", HeaderValue::from_static("/"));
    Ok(response)
}
