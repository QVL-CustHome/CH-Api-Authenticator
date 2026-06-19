use crate::domain::user::User;
use ch_auth_jwt::{Claims, JwtCodec, JwtError};
use std::time::Duration;

pub struct JwtService {
    codec: JwtCodec,
    ttl: Duration,
}

impl JwtService {
    pub fn new(secret: &str, ttl_minutes: u64) -> Self {
        Self {
            codec: JwtCodec::from_secret(secret),
            ttl: Duration::from_secs(ttl_minutes * 60),
        }
    }

    pub fn ttl_seconds(&self) -> u64 {
        self.ttl.as_secs()
    }

    pub fn issue(&self, user: &User, ip: Option<String>) -> Result<String, JwtError> {
        let sub = user
            .id
            .map(|id| id.to_hex())
            .expect("utilisateur persisté : id renseigné");
        self.codec.issue(sub, user.roles.clone(), ip, self.ttl)
    }

    pub fn validate(&self, token: &str) -> Result<Claims, JwtError> {
        self.codec.decode(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ch_auth_jwt::{Algorithm, Claims, JwtErrorKind, unix_now};
    use jsonwebtoken::{EncodingKey, Header};
    use mongodb::bson::oid::ObjectId;

    const SECRET: &str = "un-secret-de-test-suffisamment-long!!!!!";

    fn user_with_roles() -> User {
        let mut user = User::new(
            "martin@test.fr",
            "$argon2id$hash".to_string(),
            vec!["admin".to_string()],
        );
        user.id = Some(ObjectId::new());
        user
    }

    #[test]
    fn roundtrip_emission_validation() {
        let service = JwtService::new(SECRET, 15);
        let user = user_with_roles();

        let token = service.issue(&user, None).unwrap();
        let claims = service.validate(&token).unwrap();

        assert_eq!(claims.sub, user.id.unwrap().to_hex());
        assert_eq!(claims.roles, vec!["admin".to_string()]);
        assert_eq!(claims.ip, None);
        assert_eq!(claims.exp - claims.iat, 15 * 60);
    }

    #[test]
    fn claim_ip_embarque_pour_whitelist() {
        let service = JwtService::new(SECRET, 15);
        let token = service
            .issue(&user_with_roles(), Some("192.168.1.10".to_string()))
            .unwrap();
        let claims = service.validate(&token).unwrap();
        assert_eq!(claims.ip.as_deref(), Some("192.168.1.10"));
    }

    #[test]
    fn token_expire_rejete() {
        let service = JwtService::new(SECRET, 15);

        let now = unix_now();
        let claims = Claims::new("x", Vec::new(), None, now - 3600, now - 600);
        let token = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(SECRET.as_bytes()),
        )
        .unwrap();

        let err = service.validate(&token).unwrap_err();
        assert_eq!(err.kind(), &JwtErrorKind::ExpiredSignature);
    }

    #[test]
    fn mauvais_secret_rejete() {
        let service = JwtService::new(SECRET, 15);
        let autre = JwtService::new("un-autre-secret-tout-aussi-long-mais-faux", 15);

        let token = autre.issue(&user_with_roles(), None).unwrap();
        let err = service.validate(&token).unwrap_err();
        assert_eq!(err.kind(), &JwtErrorKind::InvalidSignature);
    }

    #[test]
    fn token_falsifie_rejete() {
        let service = JwtService::new(SECRET, 15);
        let token = service.issue(&user_with_roles(), None).unwrap();
        let falsifie = format!("{}AAAA", &token[..token.len() - 4]);
        assert!(service.validate(&falsifie).is_err());
    }
}
