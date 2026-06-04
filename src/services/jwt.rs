//! Émission (US-03) et validation (US-05) des JWT HS256.
//!
//! Le token embarque tout ce dont `/validate` a besoin pour répondre
//! sans aucune I/O (contrat Gateway < 100 ms) : rôles par portail,
//! flag super-admin et IP de login pour les comptes whitelist (US-04).

use crate::domain::user::User;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Identifiant utilisateur (ObjectId hexadécimal).
    pub sub: String,
    /// Rôle par portail : `{ "portail_a": "admin" }`.
    #[serde(default)]
    pub roles: HashMap<String, String>,
    /// Super-admin global : admin sur tous les portails (US-05).
    #[serde(default)]
    pub super_admin: bool,
    /// IP de login, présente uniquement pour les comptes `whitelist_only` (US-04).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    pub iat: u64,
    pub exp: u64,
}

pub struct JwtService {
    encoding: EncodingKey,
    decoding: DecodingKey,
    ttl: Duration,
}

impl JwtService {
    pub fn new(secret: &str, ttl_minutes: u64) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret.as_bytes()),
            decoding: DecodingKey::from_secret(secret.as_bytes()),
            ttl: Duration::from_secs(ttl_minutes * 60),
        }
    }

    pub fn ttl_seconds(&self) -> u64 {
        self.ttl.as_secs()
    }

    /// Émet un token signé pour un utilisateur dont l'`id` est renseigné.
    pub fn issue(
        &self,
        user: &User,
        ip: Option<String>,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let now = unix_now();
        let claims = Claims {
            sub: user
                .id
                .map(|id| id.to_hex())
                .expect("utilisateur persisté : id renseigné"),
            roles: user.roles.clone(),
            super_admin: user.is_super_admin,
            ip,
            iat: now,
            exp: now + self.ttl.as_secs(),
        };
        jsonwebtoken::encode(&Header::new(Algorithm::HS256), &claims, &self.encoding)
    }

    /// Valide signature + expiration et rend les claims. Aucune I/O (US-05).
    // Consommé en US-05 (GET /validate).
    #[allow(dead_code)]
    pub fn validate(&self, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
        let validation = Validation::new(Algorithm::HS256);
        Ok(jsonwebtoken::decode::<Claims>(token, &self.decoding, &validation)?.claims)
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("horloge système antérieure à 1970")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mongodb::bson::oid::ObjectId;

    const SECRET: &str = "un-secret-de-test-suffisamment-long!!!!!";

    fn user_with_roles() -> User {
        let mut user = User::new(
            "martin@test.fr",
            "$argon2id$hash".to_string(),
            HashMap::from([("portail_a".to_string(), "admin".to_string())]),
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
        assert_eq!(
            claims.roles.get("portail_a").map(String::as_str),
            Some("admin")
        );
        assert!(!claims.super_admin);
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
        // Token forgé avec une expiration passée (hors de la fenêtre de tolérance).
        let now = unix_now();
        let claims = Claims {
            sub: "x".to_string(),
            roles: HashMap::new(),
            super_admin: false,
            ip: None,
            iat: now - 3600,
            exp: now - 600,
        };
        let token = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(SECRET.as_bytes()),
        )
        .unwrap();

        let err = service.validate(&token).unwrap_err();
        assert_eq!(
            err.kind(),
            &jsonwebtoken::errors::ErrorKind::ExpiredSignature
        );
    }

    #[test]
    fn mauvais_secret_rejete() {
        let service = JwtService::new(SECRET, 15);
        let autre = JwtService::new("un-autre-secret-tout-aussi-long-mais-faux", 15);

        let token = autre.issue(&user_with_roles(), None).unwrap();
        let err = service.validate(&token).unwrap_err();
        assert_eq!(
            err.kind(),
            &jsonwebtoken::errors::ErrorKind::InvalidSignature
        );
    }

    #[test]
    fn token_falsifie_rejete() {
        let service = JwtService::new(SECRET, 15);
        let token = service.issue(&user_with_roles(), None).unwrap();
        let falsifie = format!("{}AAAA", &token[..token.len() - 4]);
        assert!(service.validate(&falsifie).is_err());
    }
}
