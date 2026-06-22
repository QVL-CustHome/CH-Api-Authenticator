use crate::config::TokenConfig;
use crate::domain::role::Portal;
use crate::domain::user::{User, deserialize_roles};
use jsonwebtoken::errors::Error as JwtError;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub use jsonwebtoken::errors::ErrorKind as JwtErrorKind;

const JWT_ALGORITHM: Algorithm = Algorithm::HS256;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    pub sub: String,

    #[serde(default, deserialize_with = "deserialize_roles")]
    pub roles: Vec<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,

    pub iss: String,
    pub aud: Vec<String>,

    pub iat: u64,
    pub exp: u64,
}

impl Claims {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sub: impl Into<String>,
        roles: Vec<String>,
        ip: Option<String>,
        iss: impl Into<String>,
        aud: Vec<String>,
        iat: u64,
        exp: u64,
    ) -> Self {
        Self {
            sub: sub.into(),
            roles,
            ip,
            iss: iss.into(),
            aud,
            iat,
            exp,
        }
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|owned| owned == role)
    }
}

pub struct JwtService {
    encoding: EncodingKey,
    decoding: DecodingKey,
    ttl: Duration,
    issuer: String,
    audiences_by_role: HashMap<String, String>,
}

impl JwtService {
    pub fn new(secret: &str, token: &TokenConfig) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret.as_bytes()),
            decoding: DecodingKey::from_secret(secret.as_bytes()),
            ttl: Duration::from_secs(token.ttl_minutes * 60),
            issuer: token.issuer.clone(),
            audiences_by_role: audiences_by_role(token),
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
        let now = unix_now();
        let aud = self.audiences_for(&user.roles);
        let claims = Claims::new(
            sub,
            user.roles.clone(),
            ip,
            &self.issuer,
            aud,
            now,
            now + self.ttl.as_secs(),
        );
        self.encode(&claims)
    }

    pub fn validate(&self, token: &str) -> Result<Claims, JwtError> {
        let mut validation = Validation::new(JWT_ALGORITHM);
        validation.validate_aud = false;
        Ok(jsonwebtoken::decode::<Claims>(token, &self.decoding, &validation)?.claims)
    }

    fn audiences_for(&self, roles: &[String]) -> Vec<String> {
        let mut audiences: Vec<String> = Vec::new();
        for role in roles {
            if let Some(audience) = self.audiences_by_role.get(role)
                && !audiences.iter().any(|existing| existing == audience)
            {
                audiences.push(audience.clone());
            }
        }
        audiences
    }

    fn encode(&self, claims: &Claims) -> Result<String, JwtError> {
        jsonwebtoken::encode(&Header::new(JWT_ALGORITHM), claims, &self.encoding)
    }
}

fn audiences_by_role(token: &TokenConfig) -> HashMap<String, String> {
    let mut map = HashMap::new();
    map.insert(
        Portal::Drive.role_name().to_string(),
        token.audience_drive.clone(),
    );
    map
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("horloge systeme anterieure a 1970")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header};
    use mongodb::bson::oid::ObjectId;

    const SECRET: &str = "un-secret-de-test-suffisamment-long!!!!!";

    fn token_config(ttl_minutes: u64) -> TokenConfig {
        TokenConfig {
            ttl_minutes,
            cookie_name: "ch_token".to_string(),
            cookie_secure: false,
            refresh_ttl_days: 7,
            refresh_cookie_name: "ch_refresh".to_string(),
            issuer: "ch-api-authenticator".to_string(),
            audience_drive: "ch-api-drive".to_string(),
        }
    }

    fn service(secret: &str, ttl_minutes: u64) -> JwtService {
        JwtService::new(secret, &token_config(ttl_minutes))
    }

    fn user_with_roles() -> User {
        let mut user = User::new(
            "martin@test.fr",
            "$argon2id$hash".to_string(),
            vec!["admin".to_string()],
        );
        user.id = Some(ObjectId::new());
        user
    }

    fn user_with_role(role: &str) -> User {
        let mut user = User::new(
            "martin@test.fr",
            "$argon2id$hash".to_string(),
            vec![role.to_string()],
        );
        user.id = Some(ObjectId::new());
        user
    }

    #[test]
    fn roundtrip_emission_validation() {
        let service = service(SECRET, 15);
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
        let service = service(SECRET, 15);
        let token = service
            .issue(&user_with_roles(), Some("192.168.1.10".to_string()))
            .unwrap();
        let claims = service.validate(&token).unwrap();
        assert_eq!(claims.ip.as_deref(), Some("192.168.1.10"));
    }

    #[test]
    fn issuer_embarque_a_l_emission() {
        let service = service(SECRET, 15);
        let token = service.issue(&user_with_roles(), None).unwrap();
        let claims = service.validate(&token).unwrap();
        assert_eq!(claims.iss, "ch-api-authenticator");
    }

    #[test]
    fn role_drive_produit_audience_drive() {
        let service = service(SECRET, 15);
        let token = service.issue(&user_with_role("drive"), None).unwrap();
        let claims = service.validate(&token).unwrap();
        assert_eq!(claims.aud, vec!["ch-api-drive".to_string()]);
    }

    #[test]
    fn role_sans_audience_ne_produit_aucune_audience() {
        let service = service(SECRET, 15);
        let token = service.issue(&user_with_role("admin"), None).unwrap();
        let claims = service.validate(&token).unwrap();
        assert!(claims.aud.is_empty());
    }

    #[test]
    fn token_expire_rejete() {
        let service = service(SECRET, 15);

        let now = unix_now();
        let claims = Claims::new(
            "x",
            Vec::new(),
            None,
            "ch-api-authenticator",
            Vec::new(),
            now - 3600,
            now - 600,
        );
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
        let attendu = service(SECRET, 15);
        let autre = service("un-autre-secret-tout-aussi-long-mais-faux", 15);

        let token = autre.issue(&user_with_roles(), None).unwrap();
        let err = attendu.validate(&token).unwrap_err();
        assert_eq!(err.kind(), &JwtErrorKind::InvalidSignature);
    }

    #[test]
    fn token_falsifie_rejete() {
        let service = service(SECRET, 15);
        let token = service.issue(&user_with_roles(), None).unwrap();
        let falsifie = format!("{}AAAA", &token[..token.len() - 4]);
        assert!(service.validate(&falsifie).is_err());
    }
}
