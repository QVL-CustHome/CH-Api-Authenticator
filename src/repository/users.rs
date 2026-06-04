//! Accès à la collection `users` (US-01).

use crate::domain::user::User;
use mongodb::bson::doc;
use mongodb::bson::oid::ObjectId;
use mongodb::options::IndexOptions;
use mongodb::{Collection, Database, IndexModel};

/// Code serveur MongoDB pour une violation d'index unique.
const DUPLICATE_KEY_CODE: i32 = 11000;

#[derive(Debug, thiserror::Error)]
pub enum RepositoryError {
    #[error("email déjà utilisé")]
    DuplicateEmail,
    #[error("erreur base de données : {0}")]
    Database(#[from] mongodb::error::Error),
}

#[derive(Clone)]
pub struct UserRepository {
    collection: Collection<User>,
}

impl UserRepository {
    pub fn new(db: &Database) -> Self {
        Self {
            collection: db.collection("users"),
        }
    }

    /// Crée l'index unique sur `email`. Idempotent, appelé au démarrage.
    pub async fn ensure_indexes(&self) -> Result<(), mongodb::error::Error> {
        let index = IndexModel::builder()
            .keys(doc! { "email": 1 })
            .options(IndexOptions::builder().unique(true).build())
            .build();
        self.collection.create_index(index).await?;
        Ok(())
    }

    pub async fn insert(&self, user: &User) -> Result<ObjectId, RepositoryError> {
        match self.collection.insert_one(user).await {
            Ok(result) => Ok(result
                .inserted_id
                .as_object_id()
                .expect("MongoDB génère un ObjectId à l'insertion")),
            Err(e) if is_duplicate_key(&e) => Err(RepositoryError::DuplicateEmail),
            Err(e) => Err(RepositoryError::Database(e)),
        }
    }

    pub async fn find_by_email(&self, email: &str) -> Result<Option<User>, mongodb::error::Error> {
        self.collection
            .find_one(doc! { "email": email.trim().to_lowercase() })
            .await
    }

    pub async fn find_by_id(&self, id: ObjectId) -> Result<Option<User>, mongodb::error::Error> {
        self.collection.find_one(doc! { "_id": id }).await
    }

    /// Liste paginée (US-20), triée par date de création, avec filtre
    /// optionnel par email exact (normalisé). Rend aussi le total.
    pub async fn list(
        &self,
        skip: u64,
        limit: i64,
        email: Option<&str>,
    ) -> Result<(Vec<User>, u64), mongodb::error::Error> {
        let filter = match email {
            Some(email) => doc! { "email": email.trim().to_lowercase() },
            None => doc! {},
        };
        let total = self.collection.count_documents(filter.clone()).await?;
        let mut cursor = self
            .collection
            .find(filter)
            .sort(doc! { "created_at": 1, "_id": 1 })
            .skip(skip)
            .limit(limit)
            .await?;
        let mut users = Vec::new();
        while cursor.advance().await? {
            users.push(cursor.deserialize_current()?);
        }
        Ok((users, total))
    }

    /// Remplace la map des rôles par portail (US-20). `Ok(false)` si l'id est inconnu.
    pub async fn update_roles(
        &self,
        id: ObjectId,
        roles: &std::collections::HashMap<String, String>,
    ) -> Result<bool, mongodb::error::Error> {
        let roles_bson = mongodb::bson::to_bson(roles).expect("map de chaînes sérialisable");
        let update = doc! { "$set": {
            "roles": roles_bson,
            "updated_at": mongodb::bson::DateTime::now(),
        } };
        let result = self
            .collection
            .update_one(doc! { "_id": id }, update)
            .await?;
        Ok(result.matched_count == 1)
    }

    /// Met à jour la restriction whitelist (US-20). `Ok(false)` si l'id est inconnu.
    pub async fn update_whitelist(
        &self,
        id: ObjectId,
        whitelist_only: bool,
        allowed_ips: &[String],
    ) -> Result<bool, mongodb::error::Error> {
        let update = doc! { "$set": {
            "whitelist_only": whitelist_only,
            "allowed_ips": allowed_ips,
            "updated_at": mongodb::bson::DateTime::now(),
        } };
        let result = self
            .collection
            .update_one(doc! { "_id": id }, update)
            .await?;
        Ok(result.matched_count == 1)
    }

    /// Remplace le hash du mot de passe (US-18). `Ok(false)` si l'id est inconnu.
    pub async fn update_password(
        &self,
        id: ObjectId,
        password_hash: &str,
    ) -> Result<bool, mongodb::error::Error> {
        let update = doc! { "$set": {
            "password_hash": password_hash,
            "updated_at": mongodb::bson::DateTime::now(),
        } };
        let result = self
            .collection
            .update_one(doc! { "_id": id }, update)
            .await?;
        Ok(result.matched_count == 1)
    }

    /// Change l'email (déjà normalisé par l'appelant). `Ok(false)` si l'id
    /// est inconnu ; l'unicité reste garantie par l'index (US-14).
    pub async fn update_email(&self, id: ObjectId, email: &str) -> Result<bool, RepositoryError> {
        let update = doc! { "$set": {
            "email": email,
            "updated_at": mongodb::bson::DateTime::now(),
        } };
        match self.collection.update_one(doc! { "_id": id }, update).await {
            Ok(result) => Ok(result.matched_count == 1),
            Err(e) if is_duplicate_key(&e) => Err(RepositoryError::DuplicateEmail),
            Err(e) => Err(RepositoryError::Database(e)),
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Ces tests utilisent l'instance MongoDB locale (service Windows),
    /// chacun dans une base jetable supprimée en fin de test.
    async fn test_db() -> Database {
        let client = mongodb::Client::with_uri_str("mongodb://localhost:27017")
            .await
            .expect("MongoDB locale requise pour les tests d'intégration");
        client.database(&format!("ch_auth_test_{}", ObjectId::new()))
    }

    fn user(email: &str) -> User {
        User::new(email, "$argon2id$test".to_string(), HashMap::new())
    }

    #[tokio::test]
    async fn doublon_email_renvoie_une_erreur_propre() {
        let db = test_db().await;
        let repo = UserRepository::new(&db);
        repo.ensure_indexes().await.unwrap();

        repo.insert(&user("doublon@test.fr")).await.unwrap();
        // Même email avec une casse différente : normalisé, donc rejeté aussi.
        let err = repo.insert(&user("Doublon@Test.FR")).await.unwrap_err();
        assert!(matches!(err, RepositoryError::DuplicateEmail));

        db.drop().await.unwrap();
    }

    #[tokio::test]
    async fn find_by_email_normalise_la_recherche() {
        let db = test_db().await;
        let repo = UserRepository::new(&db);
        repo.ensure_indexes().await.unwrap();

        let id = repo.insert(&user("martin@test.fr")).await.unwrap();
        let found = repo.find_by_email("  MARTIN@test.FR ").await.unwrap();
        assert_eq!(found.expect("utilisateur trouvé").id, Some(id));

        let absent = repo.find_by_email("inconnu@test.fr").await.unwrap();
        assert!(absent.is_none());

        db.drop().await.unwrap();
    }
}
