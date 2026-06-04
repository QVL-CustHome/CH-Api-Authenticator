//! Tokens opaques sécurisés : reset de mot de passe (US-17) et
//! refresh tokens (US-19).
//!
//! Le token remis au client est un secret de 32 octets aléatoires ;
//! seul son hash SHA-256 est stocké en base — un dump de la base ne
//! permet ni de réinitialiser un compte ni de rejouer une session.

use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

/// Génère un token aléatoire (64 caractères hexadécimaux, URL-safe).
pub fn generate() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Hash de stockage (SHA-256 hexadécimal).
pub fn hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_aleatoires_et_url_safe() {
        let t1 = generate();
        let t2 = generate();
        assert_eq!(t1.len(), 64);
        assert_ne!(t1, t2);
        assert!(t1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_stable_et_distinct_du_token() {
        let token = generate();
        assert_eq!(hash(&token), hash(&token));
        assert_ne!(hash(&token), token);
        assert_eq!(hash(&token).len(), 64);
    }
}
