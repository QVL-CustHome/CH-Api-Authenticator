use mongodb::bson::oid::ObjectId;
use mongodb::bson::{DateTime, Document, doc};
use mongodb::options::IndexOptions;
use mongodb::{Collection, Database, IndexModel};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginEvent {
    pub user_id: ObjectId,
    pub portals: Vec<String>,
    pub created_at: DateTime,
}

pub struct PortalConnections {
    pub portal: String,
    pub connected_users: u64,
}

#[derive(Clone)]
pub struct LoginEventRepository {
    collection: Collection<LoginEvent>,
}

impl LoginEventRepository {
    pub fn new(db: &Database) -> Self {
        Self {
            collection: db.collection("login_events"),
        }
    }

    pub async fn ensure_indexes(&self) -> Result<(), mongodb::error::Error> {
        let by_date = IndexModel::builder()
            .keys(doc! { "created_at": 1 })
            .options(IndexOptions::builder().build())
            .build();
        self.collection.create_index(by_date).await?;
        Ok(())
    }

    pub async fn record(
        &self,
        user_id: ObjectId,
        portals: &[String],
    ) -> Result<(), mongodb::error::Error> {
        self.collection
            .insert_one(LoginEvent {
                user_id,
                portals: portals.to_vec(),
                created_at: DateTime::now(),
            })
            .await?;
        Ok(())
    }

    pub async fn connected_users_by_portal(
        &self,
        since: DateTime,
    ) -> Result<Vec<PortalConnections>, mongodb::error::Error> {
        let pipeline = vec![
            doc! { "$match": { "created_at": { "$gte": since } } },
            doc! { "$unwind": "$portals" },
            doc! { "$group": { "_id": "$portals", "users": { "$addToSet": "$user_id" } } },
            doc! { "$project": { "_id": 0, "portal": "$_id", "connected_users": { "$size": "$users" } } },
        ];

        let mut cursor = self.collection.aggregate(pipeline).await?;
        let mut out = Vec::new();
        while cursor.advance().await? {
            let doc: Document = cursor.deserialize_current()?;
            let portal = doc.get_str("portal").unwrap_or_default().to_string();
            let connected_users = doc
                .get_i32("connected_users")
                .map(|v| v.max(0) as u64)
                .or_else(|_| doc.get_i64("connected_users").map(|v| v.max(0) as u64))
                .unwrap_or(0);
            out.push(PortalConnections {
                portal,
                connected_users,
            });
        }
        Ok(out)
    }
}
