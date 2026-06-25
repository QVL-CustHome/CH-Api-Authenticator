use serde::{Deserialize, Serialize};

pub const USER_DELETED_TOPIC: &str = "auth/user/deleted";
pub const USER_DELETED_TYPE: &str = "auth.user.deleted";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserDeletedEvent {
    pub event_id: String,
    pub event_type: String,
    pub sub: String,
    pub occurred_at: String,
}

impl UserDeletedEvent {
    pub fn new(event_id: String, sub: String, occurred_at: String) -> Self {
        Self {
            event_id,
            event_type: USER_DELETED_TYPE.to_string(),
            sub,
            occurred_at,
        }
    }
}
