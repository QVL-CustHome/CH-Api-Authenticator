//! Accès MongoDB : connexion fail-fast et collection `users` (US-01).

pub mod users;

use mongodb::bson::doc;
use mongodb::options::ClientOptions;
use mongodb::{Client, Database};
use std::time::Duration;

/// Délai maximum pour joindre MongoDB au démarrage.
const SERVER_SELECTION_TIMEOUT: Duration = Duration::from_secs(3);

/// Base utilisée si l'URI ne précise pas de nom de base.
const DEFAULT_DATABASE: &str = "custhome_auth";

/// Ouvre la connexion et vérifie immédiatement la disponibilité (ping).
/// Échoue en moins de [`SERVER_SELECTION_TIMEOUT`] si MongoDB est injoignable.
pub async fn connect(uri: &str) -> Result<Database, mongodb::error::Error> {
    let mut options = ClientOptions::parse(uri).await?;
    options.server_selection_timeout = Some(SERVER_SELECTION_TIMEOUT);
    let client = Client::with_options(options)?;
    let db = client
        .default_database()
        .unwrap_or_else(|| client.database(DEFAULT_DATABASE));
    db.run_command(doc! { "ping": 1 }).await?;
    Ok(db)
}
