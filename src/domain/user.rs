//! Modèle utilisateur : nom, rôles par portail, statut de compte, whitelist IP.

use mongodb::bson::DateTime;
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    /// Nom affiché de l'utilisateur (obligatoire à l'inscription).
    /// `default` pour les comptes créés avant l'ajout du champ.
    #[serde(default)]
    pub name: String,
    /// Toujours stocké en lowercase (index unique).
    pub email: String,
    /// Hash Argon2id — jamais de mot de passe en clair.
    pub password_hash: String,
    /// Rôles de l'utilisateur, globaux (valables sur tous les portails) : ex.
    /// `["admin", "editor"]`. Désérialisation tolérante : les anciens formats
    /// par portail (`{portail: "role"}` ou `{portail: ["role"]}`) sont aplatis.
    #[serde(default, deserialize_with = "deserialize_roles")]
    pub roles: Vec<String>,
    /// État du compte : un nouvel inscrit est « en attente de validation » et
    /// ne peut pas se connecter tant qu'un admin ne l'a pas activé (US-8.1).
    /// `default` = `Active` pour les comptes créés avant l'US-8.1.
    #[serde(default)]
    pub status: AccountStatus,
    /// Si `true`, le login n'est autorisé que depuis `allowed_ips` (US-04).
    #[serde(default)]
    pub whitelist_only: bool,
    /// IP simples ou plages CIDR, utilisées si `whitelist_only`.
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}

/// Désérialise la map des rôles en tolérant l'ancien format (valeur string) et
/// le nouveau (valeur tableau). `"admin"` devient `["admin"]`.
pub fn deserialize_roles<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum RolesFormat {
        Flat(Vec<String>),
        PerPortalMany(HashMap<String, Vec<String>>),
        PerPortalOne(HashMap<String, String>),
    }
    let collected = match RolesFormat::deserialize(deserializer)? {
        RolesFormat::Flat(roles) => roles,
        RolesFormat::PerPortalMany(map) => map.into_values().flatten().collect(),
        RolesFormat::PerPortalOne(map) => map.into_values().collect(),
    };
    // Dédoublonne en conservant l'ordre d'apparition.
    let mut seen = std::collections::HashSet::new();
    Ok(collected
        .into_iter()
        .filter(|role| seen.insert(role.clone()))
        .collect())
}

/// État d'un compte vis-à-vis de la connexion (US-8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    /// Créé mais non encore validé par un administrateur : connexion refusée.
    PendingValidation,
    /// Actif : connexion autorisée.
    Active,
    /// Désactivé par un administrateur : connexion refusée.
    Disabled,
}

impl Default for AccountStatus {
    /// Les comptes antérieurs à l'US-8.1 (sans champ `status`) sont actifs ;
    /// seul `/register` crée désormais en `PendingValidation`.
    fn default() -> Self {
        AccountStatus::Active
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
    fn nouveau_compte_actif_par_defaut() {
        // `User::new` crée un compte actif ; c'est `/register` qui le bascule
        // en attente. Le défaut de désérialisation (docs sans `status`) est actif.
        let user = User::new("a@b.c", "hash".to_string(), Vec::new());
        assert_eq!(user.status, AccountStatus::Active);
        assert_eq!(AccountStatus::default(), AccountStatus::Active);
        assert_eq!(user.name, "");
    }
}
