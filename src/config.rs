//! Chargement et validation de la configuration (US-00).
//!
//! Deux sources, jamais de secret dans le fichier :
//! - `config.toml` : valeurs non sensibles, surchargées par les variables
//!   d'environnement préfixées `CH__` (ex. `CH__SERVER__PORT=9000`) ;
//! - variables d'environnement dédiées aux secrets : `JWT_SECRET`,
//!   `MONGO_URI`, et le seed super-admin `ADMIN_EMAIL` / `ADMIN_PASSWORD` (US-01).

// Champs consommés progressivement par les US suivantes (mongo_uri en US-01,
// token.* en US-03, default_roles en US-02) — allow retiré à la fin du sprint.
#![allow(dead_code)]

use figment::Figment;
use figment::providers::{Env, Format, Toml};
use serde::Deserialize;
use std::collections::HashMap;

/// Taille minimale du secret JWT, en octets.
pub const MIN_JWT_SECRET_BYTES: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    // Boxé : figment::Error est volumineux (clippy::result_large_err).
    #[error("fichier de configuration invalide : {0}")]
    File(Box<figment::Error>),
    #[error("variable d'environnement requise manquante ou vide : {0}")]
    MissingSecret(&'static str),
    #[error("JWT_SECRET trop court : {0} octets (minimum {MIN_JWT_SECRET_BYTES})")]
    WeakJwtSecret(usize),
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
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub port: u16,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TokenConfig {
    /// Durée de vie de l'access token, en minutes.
    pub ttl_minutes: u64,
    /// Nom du cookie HttpOnly posé au login (US-03).
    pub cookie_name: String,
    /// Attribut Secure du cookie — `false` uniquement en dev local.
    #[serde(default)]
    pub cookie_secure: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RegistrationConfig {
    /// Rôles attribués à l'inscription : `{ portail = "rôle" }`. Vide par défaut,
    /// l'attribution passe sinon par les endpoints super-admin (sprint 2).
    #[serde(default)]
    pub default_roles: HashMap<String, String>,
}

/// Secrets chargés exclusivement depuis l'environnement.
#[derive(Clone)]
pub struct Secrets {
    pub jwt_secret: String,
    pub mongo_uri: String,
    pub admin_email: Option<String>,
    pub admin_password: Option<String>,
}

// Debug manuel : les valeurs ne doivent jamais fuiter dans les logs.
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
            .finish()
    }
}

pub struct Settings {
    pub config: Config,
    pub secrets: Secrets,
}

pub fn load(path: &str) -> Result<Settings, ConfigError> {
    let config: Config = Figment::new()
        .merge(Toml::file(path))
        .merge(Env::prefixed("CH__").split("__"))
        .extract()?;
    let secrets = load_secrets()?;
    validate_secrets(&secrets)?;
    Ok(Settings { config, secrets })
}

fn load_secrets() -> Result<Secrets, ConfigError> {
    Ok(Secrets {
        jwt_secret: require("JWT_SECRET")?,
        mongo_uri: require("MONGO_URI")?,
        admin_email: optional("ADMIN_EMAIL"),
        admin_password: optional("ADMIN_PASSWORD"),
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn secrets(jwt_secret: &str) -> Secrets {
        Secrets {
            jwt_secret: jwt_secret.to_string(),
            mongo_uri: "mongodb://localhost:27017/test".to_string(),
            admin_email: None,
            admin_password: None,
        }
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
        assert_eq!(config.server.log_level, "INFO"); // valeur par défaut
        assert_eq!(config.token.ttl_minutes, 15);
        assert!(!config.token.cookie_secure); // défaut sûr en absence de valeur
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
