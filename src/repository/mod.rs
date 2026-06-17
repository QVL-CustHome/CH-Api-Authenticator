pub mod login_events;
pub mod refresh_tokens;
pub mod reset_tokens;
pub mod roles;
pub mod settings;
pub mod users;

use mongodb::bson::doc;
use mongodb::options::ClientOptions;
use mongodb::{Client, Database};
use std::time::Duration;

const SERVER_SELECTION_TIMEOUT: Duration = Duration::from_secs(3);

const DEFAULT_DATABASE: &str = "custhome_auth";

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
