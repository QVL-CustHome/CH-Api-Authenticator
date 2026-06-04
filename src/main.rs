mod config;
mod domain;
mod error;
mod handlers;
mod middleware;
mod repository;
mod routes;
mod services;
mod state;

use state::AppState;

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

    let port = settings.config.server.port;
    let state = AppState::new(settings);
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

/// Initialise les logs. Le format JSON structuré complet (avec correlation ID)
/// sera mis en place en US-06 ; sortie lisible en attendant.
fn init_tracing(level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_new(level.to_lowercase())
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}
