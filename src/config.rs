use crate::services::rate_limit::{RateLimitConfig, RateLimitRule};
use figment::Figment;
use figment::providers::{Env, Format, Toml};
use serde::Deserialize;
use std::time::Duration;

pub const MIN_JWT_SECRET_BYTES: usize = 32;
pub const MIN_INTERNAL_API_SECRET_BYTES: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {

    #[error("fichier de configuration invalide : {0}")]
    File(Box<figment::Error>),
    #[error("variable d'environnement requise manquante ou vide : {0}")]
    MissingSecret(&'static str),
    #[error("JWT_SECRET trop court : {0} octets (minimum {MIN_JWT_SECRET_BYTES})")]
    WeakJwtSecret(usize),
    #[error(
        "INTERNAL_API_SECRET trop court : {0} octets (minimum {MIN_INTERNAL_API_SECRET_BYTES})"
    )]
    WeakInternalApiSecret(usize),
    #[error("valeur invalide pour {0} : {1}")]
    InvalidValue(&'static str, String),
}

impl From<figment::Error> for ConfigError {
    fn from(e: figment::Error) -> Self {
        ConfigError::File(Box::new(e))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub environment: Environment,
    pub server: ServerConfig,
    pub token: TokenConfig,
    #[serde(default)]
    pub registration: RegistrationConfig,
    #[serde(default)]
    pub email: EmailConfig,
    #[serde(default)]
    pub password_reset: PasswordResetConfig,
    #[serde(default)]
    pub relay: RelayConfig,
}

impl Config {
    pub fn cookie_secure_effective(&self) -> bool {
        match self.environment {
            Environment::Prod => true,
            Environment::Dev => self.token.cookie_secure,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    #[default]
    Dev,
    Prod,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PasswordResetConfig {

    #[serde(default = "default_reset_url")]
    pub url: String,

    #[serde(default = "default_reset_ttl")]
    pub ttl_minutes: u64,
}

impl Default for PasswordResetConfig {
    fn default() -> Self {
        Self {
            url: default_reset_url(),
            ttl_minutes: default_reset_ttl(),
        }
    }
}

fn default_reset_url() -> String {
    "http://localhost:3000/reset-password".to_string()
}

fn default_reset_ttl() -> u64 {
    30
}

#[derive(Debug, Clone, Deserialize)]
pub struct RelayConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_relay_host")]
    pub host: String,
    #[serde(default = "default_relay_port")]
    pub port: u16,
    #[serde(default = "default_relay_client_id")]
    pub client_id: String,
    #[serde(default = "default_relay_identity")]
    pub identity: String,
    #[serde(default = "default_relay_token_ttl")]
    pub token_ttl_seconds: u64,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            host: default_relay_host(),
            port: default_relay_port(),
            client_id: default_relay_client_id(),
            identity: default_relay_identity(),
            token_ttl_seconds: default_relay_token_ttl(),
        }
    }
}

fn default_relay_host() -> String {
    "127.0.0.1".to_string()
}

fn default_relay_port() -> u16 {
    1883
}

fn default_relay_client_id() -> String {
    "ch-api-authenticator".to_string()
}

fn default_relay_identity() -> String {
    "ch-api-authenticator".to_string()
}

fn default_relay_token_ttl() -> u64 {
    60
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub port: u16,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TokenConfig {

    pub ttl_minutes: u64,

    pub cookie_name: String,

    #[serde(default)]
    pub cookie_secure: bool,

    #[serde(default = "default_refresh_ttl_days")]
    pub refresh_ttl_days: u64,

    #[serde(default = "default_refresh_cookie_name")]
    pub refresh_cookie_name: String,

    #[serde(default = "default_jwt_issuer")]
    pub issuer: String,

    #[serde(default = "default_audience_drive")]
    pub audience_drive: String,

    #[serde(default = "default_audience_budgy")]
    pub audience_budgy: String,
}

fn default_jwt_issuer() -> String {
    "ch-api-authenticator".to_string()
}

fn default_audience_drive() -> String {
    "ch-api-drive".to_string()
}

fn default_audience_budgy() -> String {
    "ch-api-budgy".to_string()
}

fn default_refresh_ttl_days() -> u64 {
    7
}

fn default_refresh_cookie_name() -> String {
    "ch_refresh".to_string()
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RegistrationConfig {

    #[serde(default)]
    pub default_roles: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct EmailConfig {
    #[serde(default)]
    pub mode: EmailMode,

    #[serde(default = "default_email_from")]
    pub from: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EmailMode {
    #[default]
    Dev,
    Smtp,
}

#[derive(Clone)]
pub struct Secrets {
    pub jwt_secret: String,
    pub internal_api_secret: String,
    pub mongo_uri: String,
    pub admin_email: Option<String>,
    pub admin_password: Option<String>,

    pub smtp_host: Option<String>,
    pub smtp_port: Option<u16>,
    pub smtp_user: Option<String>,
    pub smtp_password: Option<String>,

    pub relay_jwt_private_key: Option<String>,
}

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secrets")
            .field("jwt_secret", &"***")
            .field("internal_api_secret", &"***")
            .field("mongo_uri", &"***")
            .field("admin_email", &self.admin_email.as_deref().map(|_| "***"))
            .field(
                "admin_password",
                &self.admin_password.as_deref().map(|_| "***"),
            )
            .field("smtp_host", &self.smtp_host.as_deref().map(|_| "***"))
            .field("smtp_user", &self.smtp_user.as_deref().map(|_| "***"))
            .field(
                "smtp_password",
                &self.smtp_password.as_deref().map(|_| "***"),
            )
            .field(
                "relay_jwt_private_key",
                &self.relay_jwt_private_key.as_deref().map(|_| "***"),
            )
            .finish_non_exhaustive()
    }
}

pub struct Settings {
    pub config: Config,
    pub secrets: Secrets,
    pub rate_limit: RateLimitConfig,
}

pub fn load(path: &str) -> Result<Settings, ConfigError> {
    let mut config: Config = Figment::new()
        .merge(Toml::file(path))
        .merge(Env::prefixed("CH__").split("__"))
        .extract()?;

    if let Some(port_str) = optional("PORT")
        && let Ok(port) = port_str.parse::<u16>()
    {
        config.server.port = port;
    }

    if let Some(issuer) = optional("JWT_ISSUER") {
        config.token.issuer = issuer;
    }

    if let Some(audience_drive) = optional("JWT_AUDIENCE_DRIVE") {
        config.token.audience_drive = audience_drive;
    }

    if let Some(audience_budgy) = optional("JWT_AUDIENCE_BUDGY") {
        config.token.audience_budgy = audience_budgy;
    }

    let secrets = load_secrets()?;
    validate_secrets(&secrets)?;
    validate_email(&config.email, &secrets)?;
    let rate_limit = load_rate_limit()?;
    Ok(Settings {
        config,
        secrets,
        rate_limit,
    })
}

fn load_rate_limit() -> Result<RateLimitConfig, ConfigError> {
    Ok(RateLimitConfig {
        login: RateLimitRule {
            max: rate_limit_max("AUTH_RATE_LIMIT_LOGIN_MAX", 5)?,
            window: rate_limit_window("AUTH_RATE_LIMIT_LOGIN_WINDOW_SECS", 300)?,
        },
        forgot: RateLimitRule {
            max: rate_limit_max("AUTH_RATE_LIMIT_FORGOT_MAX", 3)?,
            window: rate_limit_window("AUTH_RATE_LIMIT_FORGOT_WINDOW_SECS", 900)?,
        },
        refresh: RateLimitRule {
            max: rate_limit_max("AUTH_RATE_LIMIT_REFRESH_MAX", 30)?,
            window: rate_limit_window("AUTH_RATE_LIMIT_REFRESH_WINDOW_SECS", 60)?,
        },
    })
}

fn rate_limit_max(name: &'static str, default: u32) -> Result<u32, ConfigError> {
    match optional(name) {
        None => Ok(default),
        Some(raw) => raw
            .parse::<u32>()
            .ok()
            .filter(|max| *max > 0)
            .ok_or_else(|| ConfigError::InvalidValue(name, raw)),
    }
}

fn rate_limit_window(name: &'static str, default_secs: u64) -> Result<Duration, ConfigError> {
    match optional(name) {
        None => Ok(Duration::from_secs(default_secs)),
        Some(raw) => raw
            .parse::<u64>()
            .ok()
            .filter(|secs| *secs > 0)
            .map(Duration::from_secs)
            .ok_or_else(|| ConfigError::InvalidValue(name, raw)),
    }
}

fn load_secrets() -> Result<Secrets, ConfigError> {
    Ok(Secrets {
        jwt_secret: require("JWT_SECRET")?,
        internal_api_secret: require("INTERNAL_API_SECRET")?,
        mongo_uri: require("MONGO_URI")?,
        admin_email: optional("ADMIN_EMAIL"),
        admin_password: optional("ADMIN_PASSWORD"),
        smtp_host: optional("SMTP_HOST"),
        smtp_port: parse_optional_port("SMTP_PORT")?,
        smtp_user: optional("SMTP_USER"),
        smtp_password: optional("SMTP_PASSWORD"),
        relay_jwt_private_key: optional("RELAY_JWT_PRIVATE_KEY"),
    })
}

fn parse_optional_port(name: &'static str) -> Result<Option<u16>, ConfigError> {
    match optional(name) {
        None => Ok(None),
        Some(raw) => raw
            .parse::<u16>()
            .map(Some)
            .map_err(|_| ConfigError::InvalidValue(name, raw)),
    }
}

fn validate_email(email: &EmailConfig, secrets: &Secrets) -> Result<(), ConfigError> {
    if email.mode == EmailMode::Smtp && secrets.smtp_host.is_none() {
        return Err(ConfigError::MissingSecret("SMTP_HOST"));
    }
    Ok(())
}

fn require(name: &'static str) -> Result<String, ConfigError> {
    optional(name).ok_or(ConfigError::MissingSecret(name))
}

fn optional(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn validate_secrets(secrets: &Secrets) -> Result<(), ConfigError> {
    let jwt_len = secrets.jwt_secret.len();
    if jwt_len < MIN_JWT_SECRET_BYTES {
        return Err(ConfigError::WeakJwtSecret(jwt_len));
    }
    let internal_len = secrets.internal_api_secret.len();
    if internal_len < MIN_INTERNAL_API_SECRET_BYTES {
        return Err(ConfigError::WeakInternalApiSecret(internal_len));
    }
    Ok(())
}

fn default_log_level() -> String {
    "INFO".to_string()
}

fn default_email_from() -> String {
    "CustHome <no-reply@custhome.local>".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secrets(jwt_secret: &str) -> Secrets {
        Secrets {
            jwt_secret: jwt_secret.to_string(),
            internal_api_secret: "un-secret-interne-suffisamment-long-aussi!".to_string(),
            mongo_uri: "mongodb://localhost:27017/test".to_string(),
            admin_email: None,
            admin_password: None,
            smtp_host: None,
            smtp_port: None,
            smtp_user: None,
            smtp_password: None,
            relay_jwt_private_key: None,
        }
    }

    #[test]
    fn mode_smtp_sans_host_rejete_au_demarrage() {
        let email = EmailConfig {
            mode: EmailMode::Smtp,
            from: default_email_from(),
        };
        let err = validate_email(&email, &secrets("un-secret-suffisamment-long-pour-hs256!!"))
            .unwrap_err();
        assert!(matches!(err, ConfigError::MissingSecret("SMTP_HOST")));
    }

    #[test]
    fn mode_dev_sans_secrets_smtp_accepte() {
        let ok = validate_email(
            &EmailConfig::default(),
            &secrets("un-secret-suffisamment-long-pour-hs256!!"),
        );
        assert!(ok.is_ok());
    }

    #[test]
    fn secret_jwt_trop_court_rejete() {
        let err = validate_secrets(&secrets("trop-court")).unwrap_err();
        assert!(matches!(err, ConfigError::WeakJwtSecret(10)));
    }

    #[test]
    fn secret_jwt_valide_accepte() {
        let ok = validate_secrets(&secrets("un-secret-suffisamment-long-pour-hs256!!"));
        assert!(ok.is_ok());
    }

    #[test]
    fn config_toml_valide_chargee() {
        let config: Config = Figment::new()
            .merge(Toml::string(
                r#"
                [server]
                port = 8081

                [token]
                ttl_minutes = 15
                cookie_name = "ch_token"
                "#,
            ))
            .extract()
            .expect("la config minimale doit se charger");
        assert_eq!(config.server.port, 8081);
        assert_eq!(config.server.log_level, "INFO");
        assert_eq!(config.token.ttl_minutes, 15);
        assert!(!config.token.cookie_secure);
        assert!(config.registration.default_roles.is_empty());
    }

    #[test]
    fn config_toml_invalide_rejetee() {
        let result: Result<Config, _> = Figment::new()
            .merge(Toml::string("[server]\nport = \"pas-un-port\""))
            .extract();
        assert!(result.is_err());
    }

    #[test]
    fn debug_des_secrets_ne_fuite_rien() {
        let s = secrets("un-secret-suffisamment-long-pour-hs256!!");
        let dump = format!("{s:?}");
        assert!(!dump.contains("hs256"));
        assert!(!dump.contains("mongodb://"));
    }
}
