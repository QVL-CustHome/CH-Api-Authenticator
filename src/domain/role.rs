//! Catalogue des rôles attribuables (US-8.3) — un rôle est un simple nom unique.

use mongodb::bson::DateTime;
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    /// Nom du rôle (unique). Ex: `admin`, `editor`.
    pub name: String,
    pub created_at: DateTime,
}

impl Role {
    pub fn new(name: &str) -> Self {
        Self {
            id: None,
            name: name.trim().to_string(),
            created_at: DateTime::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_trim_le_nom() {
        let role = Role::new("  admin ");
        assert_eq!(role.name, "admin");
        assert!(role.id.is_none());
    }
}
