#[cfg_attr(mobile, tauri::mobile_entry_point)]
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Manager, State};

const DEFAULT_SERVER_URL: &str = "https://zenproxy.top";
const DEFAULT_CONTROLLER_URL: &str = "http://127.0.0.1:9090";
const DEFAULT_BINARY_NAME: &str = "zenproxy-client";
const DEFAULT_SECRET: &str = "zenproxy-local-secret";
const DEFAULT_PORT_START: u16 = 20001;
const DEFAULT_PORT_END: u16 = 30000;

struct AppRuntime {
    process: Mutex<Option<ManagedProcess>>,
}

struct ManagedProcess {
    child: Child,
    started_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppSettings {
    server_url: String,
    api_key: String,
    controller_url: String,
    controller_secret: String,
    binary_path: String,
    local_config_path: String,
    port_start: u16,
    port_end: u16,
    auto_bind_after_import: bool,
    default_fetch_count: u32,
    default_country: String,
    default_proxy_type: String,
    prefer_dark: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            server_url: DEFAULT_SERVER_URL.to_string(),
            api_key: String::new(),
            controller_url: DEFAULT_CONTROLLER_URL.to_string(),
            controller_secret: DEFAULT_SECRET.to_string(),
            binary_path: String::new(),
            local_config_path: String::new(),
            port_start: DEFAULT_PORT_START,
            port_end: DEFAULT_PORT_END,
            auto_bind_after_import: false,
            default_fetch_count: 50,
            default_country: String::new(),
            default_proxy_type: String::new(),
            prefer_dark: true,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AppBootstrap {
    settings: AppSettings,
    status: LocalStatus,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalStatus {
    running: bool,
    reachable: bool,
    binary_path: String,
    config_path: String,
    started_at: Option<u64>,
    version: Option<Value>,
    port_range: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemotePreviewRequest {
    server_url: String,
    api_key: String,
    count: Option<u32>,
    country: Option<String>,
    proxy_type: Option<String>,
    chatgpt: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportRequest {
    server_url: String,
    api_key: String,
    count: Option<u32>,
    country: Option<String>,
    proxy_type: Option<String>,
    chatgpt: Option<bool>,
    auto_bind: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportPreviewedRequest {
    proxies: Vec<Value>,
    auto_bind: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddManualProxyRequest {
    uri: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BatchBindRequest {
    proxy_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SubscriptionRequest {
    name: String,
    url: Option<String>,
    sub_type: Option<String>,
    content: Option<String>,
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

fn app_data_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

fn settings_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app_data_dir(app)?.join("settings.json"))
}

fn detect_binary_name() -> &'static str {
    if cfg!(windows) {
        "zenproxy-client.exe"
    } else {
        DEFAULT_BINARY_NAME
    }
}

fn resolve_sibling_candidate(path: &Path, name: &str) -> Option<PathBuf> {
    let candidate = path.join(name);
    if candidate.exists() {
        Some(candidate)
    } else {
        None
    }
}

fn detect_binary_path(app: &AppHandle) -> String {
    let name = detect_binary_name();

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(parent) = exe_path.parent() {
            if let Some(found) = resolve_sibling_candidate(parent, name) {
                return found.to_string_lossy().to_string();
            }
        }
    }

    if let Ok(current) = std::env::current_dir() {
        let direct = current.join(name);
        if direct.exists() {
            return direct.to_string_lossy().to_string();
        }

        let repo_candidate = current.join("sing-box-zenproxy").join(name);
        if repo_candidate.exists() {
            return repo_candidate.to_string_lossy().to_string();
        }
    }

    if let Ok(resource_dir) = app.path().resource_dir() {
        if let Some(found) = resolve_sibling_candidate(&resource_dir, name) {
            return found.to_string_lossy().to_string();
        }
    }

    String::new()
}

fn generated_config_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app_data_dir(app)?.join("zenproxy-client-config.json"))
}

fn load_settings(app: &AppHandle) -> Result<AppSettings, String> {
    let path = settings_path(app)?;
    if path.exists() {
        let content = fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let mut settings: AppSettings =
            serde_json::from_str(&content).map_err(|e| format!("failed to parse settings: {e}"))?;
        if settings.binary_path.is_empty() {
            settings.binary_path = detect_binary_path(app);
        }
        if settings.local_config_path.is_empty() {
            settings.local_config_path = generated_config_path(app)?.to_string_lossy().to_string();
        }
        Ok(settings)
    } else {
        let mut settings = AppSettings::default();
        settings.binary_path = detect_binary_path(app);
        settings.local_config_path = generated_config_path(app)?.to_string_lossy().to_string();
        Ok(settings)
    }
}

fn save_settings_inner(app: &AppHandle, settings: &AppSettings) -> Result<(), String> {
    let path = settings_path(app)?;
    let serialized = serde_json::to_string_pretty(settings).map_err(|e| e.to_string())?;
    fs::write(path, serialized).map_err(|e| e.to_string())
}

fn normalize_url(input: &str) -> String {
    input.trim_end_matches('/').trim().to_string()
}

fn build_local_config(settings: &AppSettings) -> Value {
    json!({
        "log": { "level": "info" },
        "experimental": {
            "clash_api": {
                "external_controller": settings.controller_url.trim_start_matches("http://"),
                "secret": settings.controller_secret,
                "zenproxy_port_start": settings.port_start,
                "zenproxy_port_end": settings.port_end
            }
        },
        "outbounds": [
            { "type": "direct", "tag": "direct" }
        ]
    })
}

fn ensure_local_config(settings: &AppSettings) -> Result<(), String> {
    let path = PathBuf::from(&settings.local_config_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let content =
        serde_json::to_string_pretty(&build_local_config(settings)).map_err(|e| e.to_string())?;
    fs::write(path, content).map_err(|e| e.to_string())
}

fn auth_header(secret: &str) -> String {
    format!("Bearer {secret}")
}

async fn local_request(
    settings: &AppSettings,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value, String> {
    let client = reqwest::Client::new();
    let url = format!("{}{}", normalize_url(&settings.controller_url), path);
    let mut request = client
        .request(method, url)
        .header("Authorization", auth_header(&settings.controller_secret));
    if let Some(payload) = body {
        request = request.json(&payload);
    }
    let response = request.send().await.map_err(|e| e.to_string())?;
    let status = response.status();
    if status == reqwest::StatusCode::NO_CONTENT {
        return Ok(json!({ "ok": true }));
    }
    let text = response.text().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(
            extract_error_message(&text).unwrap_or_else(|| format!("HTTP {status}: {text}"))
        );
    }
    if text.trim().is_empty() {
        Ok(json!({}))
    } else {
        serde_json::from_str(&text).map_err(|e| format!("invalid JSON response: {e}"))
    }
}

async fn remote_request(method: Method, url: String, body: Option<Value>) -> Result<Value, String> {
    let client = reqwest::Client::new();
    let mut request = client.request(method, url);
    if let Some(payload) = body {
        request = request.json(&payload);
    }
    let response = request.send().await.map_err(|e| e.to_string())?;
    let status = response.status();
    let text = response.text().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(
            extract_error_message(&text).unwrap_or_else(|| format!("HTTP {status}: {text}"))
        );
    }
    serde_json::from_str(&text).map_err(|e| format!("invalid JSON response: {e}"))
}

fn extract_error_message(text: &str) -> Option<String> {
    serde_json::from_str::<Value>(text).ok().and_then(|v| {
        v.get("error")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .or_else(|| {
                v.get("message")
                    .and_then(|v| v.as_str())
                    .map(ToOwned::to_owned)
            })
    })
}

async fn fetch_local_status(
    app: &AppHandle,
    runtime: &State<'_, AppRuntime>,
) -> Result<LocalStatus, String> {
    let settings = load_settings(app)?;
    let mut running = false;
    let mut started_at = None;

    if let Ok(mut guard) = runtime.process.lock() {
        if let Some(managed) = guard.as_mut() {
            match managed.child.try_wait() {
                Ok(Some(_)) => {
                    *guard = None;
                }
                Ok(None) => {
                    running = true;
                    started_at = Some(managed.started_at);
                }
                Err(_) => {
                    *guard = None;
                }
            }
        }
    }

    let version = local_request(&settings, Method::GET, "/version", None)
        .await
        .ok();
    let reachable = version.is_some();

    Ok(LocalStatus {
        running,
        reachable,
        binary_path: settings.binary_path.clone(),
        config_path: settings.local_config_path.clone(),
        started_at,
        version,
        port_range: format!("{}-{}", settings.port_start, settings.port_end),
    })
}

#[tauri::command]
async fn bootstrap(app: AppHandle, runtime: State<'_, AppRuntime>) -> Result<AppBootstrap, String> {
    let settings = load_settings(&app)?;
    let status = fetch_local_status(&app, &runtime).await?;
    Ok(AppBootstrap { settings, status })
}

#[tauri::command]
async fn save_settings(app: AppHandle, mut settings: AppSettings) -> Result<AppSettings, String> {
    settings.server_url = normalize_url(&settings.server_url);
    settings.controller_url = normalize_url(&settings.controller_url);
    if settings.local_config_path.trim().is_empty() {
        settings.local_config_path = generated_config_path(&app)?.to_string_lossy().to_string();
    }
    if settings.port_start == 0 || settings.port_end == 0 || settings.port_start > settings.port_end
    {
        return Err("port range is invalid".into());
    }
    save_settings_inner(&app, &settings)?;
    Ok(settings)
}

#[tauri::command]
async fn get_local_status(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<LocalStatus, String> {
    fetch_local_status(&app, &runtime).await
}

#[tauri::command]
async fn start_local_client(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<LocalStatus, String> {
    let settings = load_settings(&app)?;
    if settings.binary_path.trim().is_empty() {
        return Err("zenproxy-client binary path is empty".into());
    }

    let binary = PathBuf::from(&settings.binary_path);
    if !binary.exists() {
        return Err(format!("binary not found: {}", binary.display()));
    }

    ensure_local_config(&settings)?;

    let already_running = {
        let mut guard = runtime
            .process
            .lock()
            .map_err(|_| "failed to lock process state")?;
        if let Some(managed) = guard.as_mut() {
            if managed
                .child
                .try_wait()
                .map_err(|e| e.to_string())?
                .is_none()
            {
                true
            } else {
                false
            }
        } else {
            false
        }
    };

    if already_running {
        return fetch_local_status(&app, &runtime).await;
    }

    {
        let mut guard = runtime
            .process
            .lock()
            .map_err(|_| "failed to lock process state")?;
        let mut command = Command::new(&binary);
        command
            .arg("run")
            .arg("-c")
            .arg(&settings.local_config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let child = command
            .spawn()
            .map_err(|e| format!("failed to start client: {e}"))?;
        *guard = Some(ManagedProcess {
            child,
            started_at: now_ts(),
        });
    }

    std::thread::sleep(std::time::Duration::from_millis(900));
    fetch_local_status(&app, &runtime).await
}

#[tauri::command]
async fn stop_local_client(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<LocalStatus, String> {
    {
        let mut guard = runtime
            .process
            .lock()
            .map_err(|_| "failed to lock process state")?;
        if let Some(mut managed) = guard.take() {
            let _ = managed.child.kill();
            let _ = managed.child.wait();
        }
    }
    fetch_local_status(&app, &runtime).await
}

#[tauri::command]
async fn preview_remote_pool(
    _app: AppHandle,
    request: RemotePreviewRequest,
) -> Result<Value, String> {
    let server = normalize_url(&request.server_url);
    let mut url = format!(
        "{server}/api/client/fetch?api_key={}&count={}",
        request.api_key,
        request.count.unwrap_or(20)
    );
    if let Some(country) = request.country.filter(|v| !v.trim().is_empty()) {
        url.push_str(&format!("&country={country}"));
    }
    if let Some(proxy_type) = request.proxy_type.filter(|v| !v.trim().is_empty()) {
        url.push_str(&format!("&type={proxy_type}"));
    }
    if request.chatgpt.unwrap_or(false) {
        url.push_str("&chatgpt=true");
    }
    remote_request(Method::GET, url, None).await
}

#[tauri::command]
async fn import_remote_pool(app: AppHandle, request: ImportRequest) -> Result<Value, String> {
    let settings = load_settings(&app)?;
    let payload = json!({
        "server": normalize_url(&request.server_url),
        "api_key": request.api_key,
        "count": request.count.unwrap_or(10),
        "country": request.country.unwrap_or_default(),
        "type": request.proxy_type.unwrap_or_default(),
        "chatgpt": request.chatgpt.unwrap_or(false),
        "auto_bind": request.auto_bind.unwrap_or(false),
    });
    local_request(&settings, Method::POST, "/fetch", Some(payload)).await
}

#[tauri::command]
async fn import_previewed_proxies(
    app: AppHandle,
    request: ImportPreviewedRequest,
) -> Result<Value, String> {
    let settings = load_settings(&app)?;
    let mut stored_ids = Vec::new();

    for proxy in request.proxies {
        let outbound = proxy
            .get("outbound")
            .cloned()
            .ok_or_else(|| "preview item missing outbound".to_string())?;
        let created = local_request(
            &settings,
            Method::POST,
            "/store",
            Some(json!({ "outbound": outbound })),
        )
        .await?;
        if let Some(id) = created.get("id").and_then(|v| v.as_str()) {
            stored_ids.push(id.to_string());
        }
    }

    let mut bound = 0;
    if request.auto_bind && !stored_ids.is_empty() {
        let bind_result = local_request(
            &settings,
            Method::POST,
            "/bindings/batch",
            Some(json!({ "proxy_ids": stored_ids })),
        )
        .await?;
        bound = bind_result
            .get("created")
            .and_then(|v| v.as_u64())
            .unwrap_or_default() as usize;
    }

    Ok(json!({
        "added": stored_ids.len(),
        "bound": bound,
        "message": if request.auto_bind {
            format!("Imported {} proxies and created {} bindings", stored_ids.len(), bound)
        } else {
            format!("Imported {} proxies", stored_ids.len())
        }
    }))
}

#[tauri::command]
async fn list_local_pool(app: AppHandle) -> Result<Value, String> {
    let settings = load_settings(&app)?;
    local_request(&settings, Method::GET, "/store", None).await
}

#[tauri::command]
async fn add_manual_proxy(app: AppHandle, request: AddManualProxyRequest) -> Result<Value, String> {
    let settings = load_settings(&app)?;
    local_request(
        &settings,
        Method::POST,
        "/store",
        Some(json!({ "uri": request.uri.trim() })),
    )
    .await
}

#[tauri::command]
async fn delete_local_proxy(app: AppHandle, proxy_id: String) -> Result<Value, String> {
    let settings = load_settings(&app)?;
    local_request(
        &settings,
        Method::DELETE,
        &format!("/store/{proxy_id}"),
        None,
    )
    .await
}

#[tauri::command]
async fn clear_local_pool(app: AppHandle) -> Result<Value, String> {
    let settings = load_settings(&app)?;
    local_request(&settings, Method::DELETE, "/store", None).await
}

#[tauri::command]
async fn list_bindings(app: AppHandle) -> Result<Value, String> {
    let settings = load_settings(&app)?;
    local_request(&settings, Method::GET, "/bindings", None).await
}

#[tauri::command]
async fn batch_bind_selected(app: AppHandle, request: BatchBindRequest) -> Result<Value, String> {
    let settings = load_settings(&app)?;
    local_request(
        &settings,
        Method::POST,
        "/bindings/batch",
        Some(json!({ "proxy_ids": request.proxy_ids })),
    )
    .await
}

#[tauri::command]
async fn bind_all_local_pool(app: AppHandle) -> Result<Value, String> {
    let settings = load_settings(&app)?;
    local_request(
        &settings,
        Method::POST,
        "/bindings/batch",
        Some(json!({ "all": true })),
    )
    .await
}

#[tauri::command]
async fn delete_binding(app: AppHandle, tag: String) -> Result<Value, String> {
    let settings = load_settings(&app)?;
    local_request(&settings, Method::DELETE, &format!("/bindings/{tag}"), None).await
}

#[tauri::command]
async fn clear_bindings(app: AppHandle) -> Result<Value, String> {
    let settings = load_settings(&app)?;
    local_request(&settings, Method::DELETE, "/bindings/all", None).await
}

#[tauri::command]
async fn list_subscriptions(app: AppHandle) -> Result<Value, String> {
    let settings = load_settings(&app)?;
    local_request(&settings, Method::GET, "/subscriptions", None).await
}

#[tauri::command]
async fn add_subscription(app: AppHandle, request: SubscriptionRequest) -> Result<Value, String> {
    let settings = load_settings(&app)?;
    local_request(
        &settings,
        Method::POST,
        "/subscriptions",
        Some(json!({
            "name": request.name,
            "url": request.url.unwrap_or_default(),
            "type": request.sub_type.unwrap_or_else(|| "auto".into()),
            "content": request.content.unwrap_or_default(),
        })),
    )
    .await
}

#[tauri::command]
async fn refresh_subscription(app: AppHandle, subscription_id: String) -> Result<Value, String> {
    let settings = load_settings(&app)?;
    local_request(
        &settings,
        Method::POST,
        &format!("/subscriptions/{subscription_id}/refresh"),
        None,
    )
    .await
}

#[tauri::command]
async fn delete_subscription(app: AppHandle, subscription_id: String) -> Result<Value, String> {
    let settings = load_settings(&app)?;
    local_request(
        &settings,
        Method::DELETE,
        &format!("/subscriptions/{subscription_id}"),
        None,
    )
    .await
}

pub fn run() {
    tauri::Builder::default()
        .manage(AppRuntime {
            process: Mutex::new(None),
        })
        .plugin(
            tauri_plugin_log::Builder::default()
                .level(log::LevelFilter::Info)
                .build(),
        )
        .invoke_handler(tauri::generate_handler![
            bootstrap,
            save_settings,
            get_local_status,
            start_local_client,
            stop_local_client,
            preview_remote_pool,
            import_remote_pool,
            import_previewed_proxies,
            list_local_pool,
            add_manual_proxy,
            delete_local_proxy,
            clear_local_pool,
            list_bindings,
            batch_bind_selected,
            bind_all_local_pool,
            delete_binding,
            clear_bindings,
            list_subscriptions,
            add_subscription,
            refresh_subscription,
            delete_subscription
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
