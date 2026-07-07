use mongodb::bson::oid::ObjectId;
use mongodb::bson::{DateTime, doc};
use mongodb::options::IndexOptions;
use mongodb::{Collection, Database, IndexModel};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshToken {
    pub user_id: ObjectId,
    pub family_id: ObjectId,
    pub token_hash: String,
    pub expires_at: DateTime,
    pub revoked: bool,
    pub created_at: DateTime,
}

pub enum RotationOutcome {
    Rotated(RefreshToken),

    ReuseDetected(RefreshToken),

    Unknown,
}

#[derive(Clone)]
pub struct RefreshTokenRepository {
    collection: Collection<RefreshToken>,
}

impl RefreshTokenRepository {
    pub fn new(db: &Database) -> Self {
        Self {
            collection: db.collection("refresh_tokens"),
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
        let family = IndexModel::builder().keys(doc! { "family_id": 1 }).build();
        let user = IndexModel::builder().keys(doc! { "user_id": 1 }).build();
        self.collection.create_index(ttl).await?;
        self.collection.create_index(unique_hash).await?;
        self.collection.create_index(family).await?;
        self.collection.create_index(user).await?;
        Ok(())
    }

    pub async fn create(
        &self,
        user_id: ObjectId,
        family_id: ObjectId,
        token_hash: &str,
        ttl: Duration,
    ) -> Result<(), mongodb::error::Error> {
        let now = DateTime::now();
        self.collection
            .insert_one(RefreshToken {
                user_id,
                family_id,
                token_hash: token_hash.to_string(),
                expires_at: DateTime::from_millis(now.timestamp_millis() + ttl.as_millis() as i64),
                revoked: false,
                created_at: now,
            })
            .await?;
        Ok(())
    }

    pub async fn consume_for_rotation(
        &self,
        token_hash: &str,
    ) -> Result<RotationOutcome, mongodb::error::Error> {
        let rotated = self
            .collection
            .find_one_and_update(
                doc! {
                    "token_hash": token_hash,
                    "revoked": false,
                    "expires_at": { "$gt": DateTime::now() },
                },
                doc! { "$set": { "revoked": true } },
            )
            .await?;
        if let Some(token) = rotated {
            return Ok(RotationOutcome::Rotated(token));
        }

        match self
            .collection
            .find_one(doc! { "token_hash": token_hash })
            .await?
        {
            Some(token) if token.revoked => Ok(RotationOutcome::ReuseDetected(token)),
            _ => Ok(RotationOutcome::Unknown),
        }
    }

    pub async fn revoke_family(&self, family_id: ObjectId) -> Result<u64, mongodb::error::Error> {
        let result = self
            .collection
            .update_many(
                doc! { "family_id": family_id, "revoked": false },
                doc! { "$set": { "revoked": true } },
            )
            .await?;
        Ok(result.modified_count)
    }

    pub async fn revoke_all_for_user(
        &self,
        user_id: ObjectId,
    ) -> Result<u64, mongodb::error::Error> {
        let result = self
            .collection
            .update_many(
                doc! { "user_id": user_id, "revoked": false },
                doc! { "$set": { "revoked": true } },
            )
            .await?;
        Ok(result.modified_count)
    }

    pub async fn find_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<RefreshToken>, mongodb::error::Error> {
        self.collection
            .find_one(doc! { "token_hash": token_hash })
            .await
    }
}
