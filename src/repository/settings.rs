use mongodb::bson::doc;
use mongodb::{Collection, Database};
use serde::{Deserialize, Serialize};

const SETTINGS_ID: &str = "global";

#[derive(Debug, Serialize, Deserialize)]
pub struct GlobalSettings {
    #[serde(rename = "_id")]
    pub id: String,
    pub registration_enabled: bool,
}

#[derive(Clone)]
pub struct SettingsRepository {
    collection: Collection<GlobalSettings>,
}

impl SettingsRepository {
    pub fn new(db: &Database) -> Self {
        Self {
            collection: db.collection("settings"),
        }
    }

    pub async fn registration_enabled(&self) -> Result<bool, mongodb::error::Error> {
        let settings = self.collection.find_one(doc! { "_id": SETTINGS_ID }).await?;
        Ok(settings.map(|s| s.registration_enabled).unwrap_or(true))
    }

    pub async fn set_registration_enabled(
        &self,
        enabled: bool,
    ) -> Result<(), mongodb::error::Error> {
        self.collection
            .update_one(
                doc! { "_id": SETTINGS_ID },
                doc! { "$set": { "registration_enabled": enabled } },
            )
            .upsert(true)
            .await?;
        Ok(())
    }
}
