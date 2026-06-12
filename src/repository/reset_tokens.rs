use mongodb::bson::oid::ObjectId;
use mongodb::bson::{DateTime, doc};
use mongodb::options::IndexOptions;
use mongodb::{Collection, Database, IndexModel};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Serialize, Deserialize)]
pub struct ResetToken {
    pub user_id: ObjectId,
    pub token_hash: String,
    pub expires_at: DateTime,
    pub used: bool,
    pub created_at: DateTime,
}

#[derive(Clone)]
pub struct ResetTokenRepository {
    collection: Collection<ResetToken>,
}

impl ResetTokenRepository {
    pub fn new(db: &Database) -> Self {
        Self {
            collection: db.collection("password_reset_tokens"),
        }
    }

    pub async fn ensure_indexes(&self) -> Result<(), mongodb::error::Error> {
        let ttl = IndexModel::builder()
            .keys(doc! { "expires_at": 1 })
            .options(
                IndexOptions::builder()
                    .expire_after(Duration::from_secs(0))
                    .build(),
            )
            .build();
        let unique_hash = IndexModel::builder()
            .keys(doc! { "token_hash": 1 })
            .options(IndexOptions::builder().unique(true).build())
            .build();
        self.collection.create_index(ttl).await?;
        self.collection.create_index(unique_hash).await?;
        Ok(())
    }

    pub async fn replace_for_user(
        &self,
        user_id: ObjectId,
        token_hash: &str,
        ttl: Duration,
    ) -> Result<(), mongodb::error::Error> {
        self.collection
            .delete_many(doc! { "user_id": user_id })
            .await?;
        let now = DateTime::now();
        let expires_at = DateTime::from_millis(now.timestamp_millis() + ttl.as_millis() as i64);
        self.collection
            .insert_one(ResetToken {
                user_id,
                token_hash: token_hash.to_string(),
                expires_at,
                used: false,
                created_at: now,
            })
            .await?;
        Ok(())
    }

    pub async fn consume(
        &self,
        token_hash: &str,
    ) -> Result<Option<ResetToken>, mongodb::error::Error> {
        self.collection
            .find_one_and_update(
                doc! {
                    "token_hash": token_hash,
                    "used": false,
                    "expires_at": { "$gt": DateTime::now() },
                },
                doc! { "$set": { "used": true } },
            )
            .await
    }

    pub async fn count_for_user(&self, user_id: ObjectId) -> Result<u64, mongodb::error::Error> {
        self.collection
            .count_documents(doc! { "user_id": user_id })
            .await
    }
}
