use crate::domain::role::{Portal, Role};
use mongodb::bson::doc;
use mongodb::bson::oid::ObjectId;
use mongodb::options::IndexOptions;
use mongodb::{Collection, Database, IndexModel};

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

    pub async fn ensure_indexes(&self) -> Result<(), mongodb::error::Error> {
        let index = IndexModel::builder()
            .keys(doc! { "name": 1 })
            .options(IndexOptions::builder().unique(true).build())
            .build();
        self.collection.create_index(index).await?;
        Ok(())
    }

    pub async fn ensure_portal_roles(&self) -> Result<(), mongodb::error::Error> {
        let known_portals: Vec<String> = Portal::ALL
            .iter()
            .map(|portal| portal.role_name().to_string())
            .collect();
        self.collection
            .delete_many(doc! { "portal": { "$nin": known_portals } })
            .await?;
        for portal in Portal::ALL {
            let role = Role::portal_role(portal);
            match self.insert(&role).await {
                Ok(_) | Err(RoleError::Duplicate) => {}
                Err(RoleError::Database(e)) => return Err(e),
            }
        }
        Ok(())
    }

    pub async fn find_by_id(&self, id: ObjectId) -> Result<Option<Role>, mongodb::error::Error> {
        self.collection.find_one(doc! { "_id": id }).await
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

    pub async fn delete(&self, id: ObjectId) -> Result<bool, mongodb::error::Error> {
        let result = self.collection.delete_one(doc! { "_id": id }).await?;
        Ok(result.deleted_count == 1)
    }

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
