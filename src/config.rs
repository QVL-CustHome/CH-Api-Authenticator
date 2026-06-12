use figment::Figment;
use figment::providers::{Env, Format, Toml};
use serde::Deserialize;

pub const MIN_JWT_SECRET_BYTES: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {

    #[error("fichier de configuration invalide : {0}")]
    File(Box<figment::Error>),
    #[error("variable d'environnement requise manquante ou vide : {0}")]
    MissingSecret(&'static str),
    #[error("JWT_SECRET trop court : {0} octets (minimum {MIN_JWT_SECRET_BYTES})")]
    WeakJwtSecret(usize),
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
    pub server: ServerConfig,
    pub token: TokenConfig,
    #[serde(default)]
    pub registration: RegistrationConfig,
    #[serde(default)]
    pub email: EmailConfig,
    #[serde(default)]
    pub password_reset: PasswordResetConfig,
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
    pub mongo_uri: String,
    pub admin_email: Option<String>,
    pub admin_password: Option<String>,

    pub smtp_host: Option<String>,
    pub smtp_port: Option<u16>,
    pub smtp_user: Option<String>,
    pub smtp_password: Option<String>,
}

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secrets")
            .field("jwt_secret", &"***")
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
            .finish_non_exhaustive()
    }
}

pub struct Settings {
    pub config: Config,
    pub secrets: Secrets,
}

pub fn load(path: &str) -> Result<Settings, ConfigError> {
    let mut config: Config = Figment::new()
        .merge(Toml::file(path))
        .merge(Env::prefixed("CH__").split("__"))
        .extract()?;

    if let Some(port_str) = optional("PORT") {
        if let Ok(port) = port_str.parse::<u16>() {
            config.server.port = port;
        }
    }

    let secrets = load_secrets()?;
    validate_secrets(&secrets)?;
    validate_email(&config.email, &secrets)?;
    Ok(Settings { config, secrets })
}

fn load_secrets() -> Result<Secrets, ConfigError> {
    Ok(Secrets {
        jwt_secret: require("JWT_SECRET")?,
        mongo_uri: require("MONGO_URI")?,
        admin_email: optional("ADMIN_EMAIL"),
        admin_password: optional("ADMIN_PASSWORD"),
        smtp_host: optional("SMTP_HOST"),
        smtp_port: parse_optional_port("SMTP_PORT")?,
        smtp_user: optional("SMTP_USER"),
        smtp_password: optional("SMTP_PASSWORD"),
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
    let len = secrets.jwt_secret.len();
    if len < MIN_JWT_SECRET_BYTES {
        return Err(ConfigError::WeakJwtSecret(len));
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
            mongo_uri: "mongodb://localhost:27017/test".to_string(),
            admin_email: None,
            admin_password: None,
            smtp_host: None,
            smtp_port: None,
            smtp_user: None,
            smtp_password: None,
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
