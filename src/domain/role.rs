use mongodb::bson::DateTime;
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Portal {
    Admin,
    Drive,
    Home,
}

impl Portal {
    pub const ALL: [Portal; 3] = [Portal::Admin, Portal::Drive, Portal::Home];

    pub fn role_name(self) -> &'static str {
        match self {
            Portal::Admin => "admin",
            Portal::Drive => "drive",
            Portal::Home => "home",
        }
    }

    pub fn from_portal_header(value: &str) -> Option<Portal> {
        match value {
            "portail_admin" => Some(Portal::Admin),
            "portail_drive" => Some(Portal::Drive),
            "portail_home" => Some(Portal::Home),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RoleKind {
    Portal,
    Sub,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub name: String,
    pub portal: Portal,
    pub kind: RoleKind,
    pub created_at: DateTime,
}

impl Role {
    pub fn portal_role(portal: Portal) -> Self {
        Self {
            id: None,
            name: portal.role_name().to_string(),
            portal,
            kind: RoleKind::Portal,
            created_at: DateTime::now(),
        }
    }

    pub fn sub_role(name: &str, portal: Portal) -> Self {
        Self {
            id: None,
            name: name.trim().to_string(),
            portal,
            kind: RoleKind::Sub,
            created_at: DateTime::now(),
        }
    }

    pub fn is_portal_role(&self) -> bool {
        matches!(self.kind, RoleKind::Portal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sub_role_trim_le_nom() {
        let role = Role::sub_role("  editor ", Portal::Admin);
        assert_eq!(role.name, "editor");
        assert_eq!(role.portal, Portal::Admin);
        assert_eq!(role.kind, RoleKind::Sub);
        assert!(role.id.is_none());
    }

    #[test]
    fn portal_role_porte_le_nom_du_portail() {
        let role = Role::portal_role(Portal::Drive);
        assert_eq!(role.name, "drive");
        assert!(role.is_portal_role());
    }
}
