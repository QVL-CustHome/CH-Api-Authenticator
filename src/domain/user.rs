use mongodb::bson::DateTime;
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    #[serde(default)]
    pub name: String,

    pub email: String,

    pub password_hash: String,

    #[serde(default, deserialize_with = "ch_auth_jwt::deserialize_roles")]
    pub roles: Vec<String>,

    #[serde(default)]
    pub status: AccountStatus,

    #[serde(default)]
    pub whitelist_only: bool,

    #[serde(default)]
    pub allowed_ips: Vec<String>,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {

    PendingValidation,

    Active,

    Disabled,
}

impl Default for AccountStatus {
    fn default() -> Self {
        AccountStatus::PendingValidation
    }
}

impl User {
    pub fn new(email: &str, password_hash: String, roles: Vec<String>) -> Self {
        let now = DateTime::now();
        Self {
            id: None,
            name: String::new(),
            email: email.trim().to_lowercase(),
            password_hash,
            roles,
            status: AccountStatus::Active,
            whitelist_only: false,
            allowed_ips: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_normalise_en_lowercase() {
        let user = User::new("  Martin@Example.COM ", "hash".to_string(), Vec::new());
        assert_eq!(user.email, "martin@example.com");
        assert!(user.roles.is_empty());
        assert!(!user.whitelist_only);
        assert!(user.allowed_ips.is_empty());
    }

    #[test]
    fn statut_par_defaut_non_permissif() {
        assert_eq!(AccountStatus::default(), AccountStatus::PendingValidation);
    }

    #[test]
    fn nouveau_compte_via_constructeur_actif() {
        let user = User::new("a@b.c", "hash".to_string(), Vec::new());
        assert_eq!(user.status, AccountStatus::Active);
        assert_eq!(user.name, "");
    }

    #[test]
    fn user_deserialise_sans_statut_est_en_attente() {
        let reference = User::new("x@y.z", "h".to_string(), Vec::new());
        let mut document = mongodb::bson::to_document(&reference).unwrap();
        document.remove("status");
        let user: User = mongodb::bson::from_document(document).unwrap();
        assert_eq!(user.status, AccountStatus::PendingValidation);
    }
}
