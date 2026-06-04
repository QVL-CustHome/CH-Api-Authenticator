//! Modèle utilisateur : rôles par portail, super-admin global, whitelist IP (US-01).

use mongodb::bson::DateTime;
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    /// Toujours stocké en lowercase (index unique).
    pub email: String,
    /// Hash Argon2id — jamais de mot de passe en clair.
    pub password_hash: String,
    /// Rôle par portail : `{ "portail_a": "admin", "portail_b": "user" }`.
    #[serde(default)]
    pub roles: HashMap<String, String>,
    /// Super-admin global, au-dessus des portails (admin partout).
    #[serde(default)]
    pub is_super_admin: bool,
    /// Si `true`, le login n'est autorisé que depuis `allowed_ips` (US-04).
    #[serde(default)]
    pub whitelist_only: bool,
    /// IP simples ou plages CIDR, utilisées si `whitelist_only`.
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}

impl User {
    pub fn new(email: &str, password_hash: String, roles: HashMap<String, String>) -> Self {
        let now = DateTime::now();
        Self {
            id: None,
            email: email.trim().to_lowercase(),
            password_hash,
            roles,
            is_super_admin: false,
            whitelist_only: false,
            allowed_ips: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }

    pub fn new_super_admin(email: &str, password_hash: String) -> Self {
        Self {
            is_super_admin: true,
            ..Self::new(email, password_hash, HashMap::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_normalise_en_lowercase() {
        let user = User::new("  Martin@Example.COM ", "hash".to_string(), HashMap::new());
        assert_eq!(user.email, "martin@example.com");
        assert!(!user.is_super_admin);
        assert!(!user.whitelist_only);
        assert!(user.allowed_ips.is_empty());
    }

    #[test]
    fn super_admin_a_le_flag_et_aucun_role_portail() {
        let admin = User::new_super_admin("admin@custhome.local", "hash".to_string());
        assert!(admin.is_super_admin);
        assert!(admin.roles.is_empty());
    }
}
