use ch_api_authenticator::config::{Config, Environment};
use figment::Figment;
use figment::providers::{Format, Toml};

fn config_with(environment: Environment, cookie_secure: bool) -> Config {
    let toml = format!(
        r#"
        environment = "{}"

        [server]
        port = 8081

        [token]
        ttl_minutes = 15
        cookie_name = "ch_token"
        cookie_secure = {}
        "#,
        match environment {
            Environment::Dev => "dev",
            Environment::Prod => "prod",
        },
        cookie_secure,
    );
    Figment::new()
        .merge(Toml::string(&toml))
        .extract()
        .expect("config valide")
}

#[test]
fn dev_avec_cookie_secure_false_donne_secure_effectif_false() {
    let config = config_with(Environment::Dev, false);
    assert!(!config.cookie_secure_effective());
}

#[test]
fn dev_avec_cookie_secure_true_donne_secure_effectif_true() {
    let config = config_with(Environment::Dev, true);
    assert!(config.cookie_secure_effective());
}

#[test]
fn prod_avec_cookie_secure_false_force_secure_effectif_true() {
    let config = config_with(Environment::Prod, false);
    assert!(config.cookie_secure_effective());
}

#[test]
fn prod_avec_cookie_secure_true_reste_secure_effectif_true() {
    let config = config_with(Environment::Prod, true);
    assert!(config.cookie_secure_effective());
}

#[test]
fn environnement_par_defaut_est_dev() {
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
        .expect("config minimale valide");
    assert_eq!(config.environment, Environment::Dev);
    assert!(!config.cookie_secure_effective());
}

#[test]
fn environnement_invalide_fait_echouer_le_chargement() {
    let result: Result<Config, _> = Figment::new()
        .merge(Toml::string(
            r#"
            environment = "preprod"

            [server]
            port = 8081

            [token]
            ttl_minutes = 15
            cookie_name = "ch_token"
            "#,
        ))
        .extract();
    assert!(result.is_err());
}
