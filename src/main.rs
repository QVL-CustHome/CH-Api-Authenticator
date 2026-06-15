use ch_api_authenticator::config;
use ch_api_authenticator::domain::user::User;
use ch_api_authenticator::middleware::auth::ADMIN_ROLE;
use ch_api_authenticator::repository;
use ch_api_authenticator::repository::users::RepositoryError;
use ch_api_authenticator::routes;
use ch_api_authenticator::services;
use ch_api_authenticator::state::AppState;

#[tokio::main]
async fn main() {

    dotenvy::dotenv().ok();

    let settings = match config::load("config.toml") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Démarrage impossible — configuration invalide : {e}");
            std::process::exit(1);
        }
    };

    init_tracing(&settings.config.server.log_level);

    let mailer = match ch_api_authenticator::services::mailer::Mailer::from_settings(&settings) {
        Ok(m) => m,
        Err(e) => {
            tracing::error!(error = %e, "Configuration email invalide");
            eprintln!("Démarrage impossible — configuration email invalide : {e}");
            std::process::exit(1);
        }
    };

    let db = match repository::connect(&settings.secrets.mongo_uri).await {
        Ok(db) => db,
        Err(e) => {
            tracing::error!(error = %e, "MongoDB injoignable");
            eprintln!("Démarrage impossible — MongoDB injoignable : {e}");
            std::process::exit(1);
        }
    };

    let state = AppState::new(settings, db, mailer);

    let indexes = async {
        state.users.ensure_indexes().await?;
        state.roles.ensure_indexes().await?;
        state.reset_tokens.ensure_indexes().await?;
        state.refresh_tokens.ensure_indexes().await
    };
    if let Err(e) = indexes.await {
        tracing::error!(error = %e, "Création des index impossible");
        eprintln!("Démarrage impossible — création des index MongoDB en échec : {e}");
        std::process::exit(1);
    }

    if let Err(e) = state.roles.ensure_portal_roles().await {
        tracing::error!(error = %e, "Seed des rôles portail en échec");
        eprintln!("Démarrage impossible — seed des rôles portail en échec : {e}");
        std::process::exit(1);
    }

    if let Err(e) = seed_admin(&state).await {
        tracing::error!(error = %e, "Seed de l'administrateur en échec");
        eprintln!("Démarrage impossible — seed de l'administrateur en échec : {e}");
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

async fn seed_admin(state: &AppState) -> Result<(), String> {
    let secrets = &state.settings.secrets;
    let (Some(email), Some(password)) = (&secrets.admin_email, &secrets.admin_password) else {
        tracing::info!("Seed admin ignoré : ADMIN_EMAIL / ADMIN_PASSWORD absents");
        return Ok(());
    };

    match state
        .users
        .find_by_email(email)
        .await
        .map_err(|e| e.to_string())?
    {
        Some(existing) => {
            if !existing.roles.iter().any(|r| r == ADMIN_ROLE) {
                let mut roles = existing.roles.clone();
                roles.push(ADMIN_ROLE.to_string());
                state
                    .users
                    .update_roles(existing.id.expect("utilisateur persisté"), &roles)
                    .await
                    .map_err(|e| e.to_string())?;
                tracing::info!("Rôle admin ajouté au compte administrateur existant");
            } else {
                tracing::info!("Administrateur déjà présent avec le rôle, seed ignoré");
            }
            Ok(())
        }
        None => {
            let password_hash = services::password::hash(password).map_err(|e| e.to_string())?;
            let mut user = User::new(email, password_hash, vec![ADMIN_ROLE.to_string()]);
            user.name = "Administrateur".to_string();
            match state.users.insert(&user).await {
                Ok(id) => {
                    tracing::info!(user_id = %id, "Administrateur créé");
                    Ok(())
                }
                Err(RepositoryError::DuplicateEmail) => {
                    tracing::info!("Administrateur déjà présent, seed ignoré");
                    Ok(())
                }
                Err(e) => Err(e.to_string()),
            }
        }
    }
}

fn init_tracing(level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_new(level.to_lowercase())
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .init();
}
