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
