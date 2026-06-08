//! Accès à la collection `roles` : catalogue des noms de rôles (US-8.3).

use crate::domain::role::Role;
use mongodb::bson::doc;
use mongodb::bson::oid::ObjectId;
use mongodb::options::IndexOptions;
use mongodb::{Collection, Database, IndexModel};

/// Code serveur MongoDB pour une violation d'index unique.
const DUPLICATE_KEY_CODE: i32 = 11000;

#[derive(Debug, thiserror::Error)]
pub enum RoleError {
    #[error("rôle déjà défini")]
    Duplicate,
    #[error("erreur base de données : {0}")]
    Database(#[from] mongodb::error::Error),
}

#[derive(Clone)]
pub struct RoleRepository {
    collection: Collection<Role>,
}

impl RoleRepository {
    pub fn new(db: &Database) -> Self {
        Self {
            collection: db.collection("roles"),
        }
    }

    /// Index unique sur `name`. Idempotent, appelé au démarrage.
    pub async fn ensure_indexes(&self) -> Result<(), mongodb::error::Error> {
        let index = IndexModel::builder()
            .keys(doc! { "name": 1 })
            .options(IndexOptions::builder().unique(true).build())
            .build();
        self.collection.create_index(index).await?;
        Ok(())
    }

    pub async fn insert(&self, role: &Role) -> Result<ObjectId, RoleError> {
        match self.collection.insert_one(role).await {
            Ok(result) => Ok(result
                .inserted_id
                .as_object_id()
                .expect("MongoDB génère un ObjectId à l'insertion")),
            Err(e) if is_duplicate_key(&e) => Err(RoleError::Duplicate),
            Err(e) => Err(RoleError::Database(e)),
        }
    }

    /// Liste les rôles, triés par nom.
    pub async fn list(&self) -> Result<Vec<Role>, mongodb::error::Error> {
        let mut cursor = self
            .collection
            .find(doc! {})
            .sort(doc! { "name": 1 })
            .await?;
        let mut roles = Vec::new();
        while cursor.advance().await? {
            roles.push(cursor.deserialize_current()?);
        }
        Ok(roles)
    }

    /// Supprime un rôle. `Ok(false)` si l'id est inconnu.
    pub async fn delete(&self, id: ObjectId) -> Result<bool, mongodb::error::Error> {
        let result = self.collection.delete_one(doc! { "_id": id }).await?;
        Ok(result.deleted_count == 1)
    }

    /// Vrai si le rôle `name` existe (validation d'attribution, US-8.3).
    pub async fn exists(&self, name: &str) -> Result<bool, mongodb::error::Error> {
        let found = self
            .collection
            .find_one(doc! { "name": name.trim() })
            .await?;
        Ok(found.is_some())
    }
}

fn is_duplicate_key(e: &mongodb::error::Error) -> bool {
    use mongodb::error::{ErrorKind, WriteFailure};
    matches!(
        &*e.kind,
        ErrorKind::Write(WriteFailure::WriteError(write_error))
            if write_error.code == DUPLICATE_KEY_CODE
    )
}
