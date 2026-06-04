use ch_api_authenticator::config::{self, Secrets};
use ch_api_authenticator::domain::user::User;
use ch_api_authenticator::repository;
use ch_api_authenticator::repository::users::{RepositoryError, UserRepository};
use ch_api_authenticator::routes;
use ch_api_authenticator::services;
use ch_api_authenticator::state::AppState;

#[tokio::main]
async fn main() {
    // Charge .env en développement (silencieux si absent).
    dotenvy::dotenv().ok();

    // US-00 : échec au démarrage avec message explicite si la configuration est invalide.
    let settings = match config::load("config.toml") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Démarrage impossible — configuration invalide : {e}");
            std::process::exit(1);
        }
    };

    init_tracing(&settings.config.server.log_level);

    // US-01 : échec contrôlé et loggé si MongoDB est injoignable.
    let db = match repository::connect(&settings.secrets.mongo_uri).await {
        Ok(db) => db,
        Err(e) => {
            tracing::error!(error = %e, "MongoDB injoignable");
            eprintln!("Démarrage impossible — MongoDB injoignable : {e}");
            std::process::exit(1);
        }
    };

    let state = AppState::new(settings, db);

    // US-01 : index unique sur email, idempotent.
    if let Err(e) = state.users.ensure_indexes().await {
        tracing::error!(error = %e, "Création des index impossible");
        eprintln!("Démarrage impossible — création des index MongoDB en échec : {e}");
        std::process::exit(1);
    }

    // US-01 : seed du premier super-admin (créé uniquement s'il n'existe pas).
    if let Err(e) = seed_super_admin(&state.users, &state.settings.secrets).await {
        tracing::error!(error = %e, "Seed du super-admin en échec");
        eprintln!("Démarrage impossible — seed du super-admin en échec : {e}");
        std::process::exit(1);
    }

    let port = state.settings.config.server.port;
    let app = routes::router(state);

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Démarrage impossible — écoute sur {addr} refusée : {e}");
            std::process::exit(1);
        }
    };

    tracing::info!(%addr, version = env!("CARGO_PKG_VERSION"), "CH-Api-Authenticator démarré");
    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("Erreur serveur : {e}");
        std::process::exit(1);
    }
}

/// Crée le premier super-admin depuis ADMIN_EMAIL / ADMIN_PASSWORD.
/// Sans effet si les variables sont absentes ou si le compte existe déjà.
async fn seed_super_admin(users: &UserRepository, secrets: &Secrets) -> Result<(), String> {
    let (Some(email), Some(password)) = (&secrets.admin_email, &secrets.admin_password) else {
        tracing::info!("Seed super-admin ignoré : ADMIN_EMAIL / ADMIN_PASSWORD absents");
        return Ok(());
    };

    if users
        .find_by_email(email)
        .await
        .map_err(|e| e.to_string())?
        .is_some()
    {
        tracing::info!("Super-admin déjà présent, seed ignoré");
        return Ok(());
    }

    let password_hash = services::password::hash(password).map_err(|e| e.to_string())?;
    match users
        .insert(&User::new_super_admin(email, password_hash))
        .await
    {
        Ok(id) => {
            tracing::info!(user_id = %id, "Super-admin créé");
            Ok(())
        }
        // Démarrages concurrents : un autre process l'a créé entre-temps.
        Err(RepositoryError::DuplicateEmail) => {
            tracing::info!("Super-admin déjà présent, seed ignoré");
            Ok(())
        }
        Err(e) => Err(e.to_string()),
    }
}

/// Initialise les logs JSON structurés (US-06), niveau configurable
/// (DEBUG/INFO/WARN/ERROR — cohérent avec la Gateway). Le correlation id
/// est porté par le span `requete` (voir `middleware::tracing`).
fn init_tracing(level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_new(level.to_lowercase())
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .init();
}
