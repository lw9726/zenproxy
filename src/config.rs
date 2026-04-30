use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub singbox: SingboxConfig,
    pub database: DatabaseConfig,
    pub validation: ValidationConfig,
    pub quality: QualityConfig,
    pub oauth: OAuthConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub subscription: SubscriptionConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub admin_password: String,
    #[serde(default = "default_min_trust_level")]
    pub min_trust_level: i32,
}

fn default_min_trust_level() -> i32 {
    1
}

#[derive(Debug, Clone, Deserialize)]
pub struct OAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    #[serde(default = "default_true")]
    pub allow_account_login: bool,
    #[serde(default = "default_true")]
    pub allow_linux_do_login: bool,
    #[serde(default)]
    pub allow_registration: bool,
    #[serde(default = "default_true")]
    pub allow_new_users: bool,
}

fn default_true() -> bool {
    true
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            allow_account_login: true,
            allow_linux_do_login: true,
            allow_registration: false,
            allow_new_users: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SingboxConfig {
    pub binary_path: PathBuf,
    pub config_path: PathBuf,
    pub base_port: u16,
    #[serde(default = "default_max_proxies")]
    pub max_proxies: usize,
    #[serde(default = "default_api_port")]
    pub api_port: u16,
    pub api_secret: Option<String>,
}

fn default_max_proxies() -> usize {
    300
}

fn default_api_port() -> u16 {
    9090
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub path: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ValidationConfig {
    pub url: String,
    pub timeout_secs: u64,
    pub concurrency: usize,
    pub interval_mins: u64,
    pub error_threshold: u32,
    /// How many port slots to reserve for validation/quality-check per round.
    /// The rest stay with Valid proxies serving users. Default 30.
    #[serde(default = "default_validation_batch")]
    pub batch_size: usize,
}

fn default_validation_batch() -> usize {
    30
}

#[derive(Debug, Clone, Deserialize)]
pub struct QualityConfig {
    pub interval_mins: u64,
    pub concurrency: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SubscriptionConfig {
    #[serde(default)]
    pub auto_refresh_interval_mins: u64, // 0 = disabled
    #[serde(default = "default_subscription_daily_refresh_time")]
    pub auto_refresh_daily_at: String,
    #[serde(default = "default_subscription_daily_refresh_timezone")]
    pub auto_refresh_timezone: String,
}

impl Default for SubscriptionConfig {
    fn default() -> Self {
        Self {
            auto_refresh_interval_mins: 0,
            auto_refresh_daily_at: default_subscription_daily_refresh_time(),
            auto_refresh_timezone: default_subscription_daily_refresh_timezone(),
        }
    }
}

fn default_subscription_daily_refresh_time() -> String {
    "04:00".to_string()
}

fn default_subscription_daily_refresh_timezone() -> String {
    "Asia/Shanghai".to_string()
}

impl AppConfig {
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string("config.toml")
            .unwrap_or_else(|_| include_str!("../config.toml").to_string());
        let config: AppConfig = toml::from_str(&content)?;
        Ok(config)
    }
}
